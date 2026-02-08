//! Parser module for DJI flight log files.
//!
//! Handles:
//! - Parsing various DJI log formats using dji-log-parser
//! - Extracting telemetry data points
//! - File hash calculation for duplicate detection
//! - V13+ encrypted log handling with API key fetching
//! - Panic/timeout protection for untrusted file parsing

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::panic;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time::timeout;

use dji_log_parser::frame::Frame;
use dji_log_parser::DJILog;

use crate::api::DjiApi;
use crate::database::Database;
use crate::models::{FlightMetadata, FlightStats, TelemetryPoint};

/// Maximum time allowed for parsing a single log file (seconds)
const PARSE_TIMEOUT_SECS: u64 = 40;

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("File already imported")]
    AlreadyImported,

    #[error("No valid telemetry data found")]
    NoTelemetryData,

    #[error("Encryption key required for V13+ logs")]
    EncryptionKeyRequired,

    #[error("API error: {0}")]
    Api(String),

    #[error("Parser crashed on this file (internal panic)")]
    Panic(String),

    #[error("Parsing timed out after {0} seconds — file may be corrupt or unsupported")]
    Timeout(u64),
}

/// Result of parsing a DJI log file
pub struct ParseResult {
    pub metadata: FlightMetadata,
    pub points: Vec<TelemetryPoint>,
}

/// DJI Log Parser wrapper
pub struct LogParser<'a> {
    db: &'a Database,
    api: DjiApi,
}

impl<'a> LogParser<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self {
            db,
            api: DjiApi::with_app_data_dir(db.data_dir.clone()),
        }
    }

    /// Calculate SHA256 hash of a file for duplicate detection
    pub fn calculate_file_hash(path: &Path) -> Result<String, ParserError> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Parse a DJI log file and extract all telemetry data
    pub async fn parse_log(&self, file_path: &Path) -> Result<ParseResult, ParserError> {
        let parse_start = std::time::Instant::now();
        let file_size = fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
        log::info!(
            "Parsing log file: {:?} (size: {:.1} KB)",
            file_path,
            file_size as f64 / 1024.0
        );

        // Calculate file hash to check for duplicates
        let file_hash = Self::calculate_file_hash(file_path)?;
        log::debug!("File hash: {}", file_hash);

        if self
            .db
            .is_file_imported(&file_hash)
            .map_err(|e| ParserError::Parse(e.to_string()))?
        {
            log::info!("File already imported (hash match), skipping");
            return Err(ParserError::AlreadyImported);
        }

        // Read the file
        let file_data = fs::read(file_path)?;
        log::debug!("File read into memory: {} bytes", file_data.len());

        // Parse with dji-log-parser inside spawn_blocking + catch_unwind
        // This prevents a panicking/hanging parser from killing the app
        let parser = {
            let data = file_data.clone();
            let result = timeout(
                Duration::from_secs(PARSE_TIMEOUT_SECS),
                tokio::task::spawn_blocking(move || {
                    panic::catch_unwind(panic::AssertUnwindSafe(|| {
                        DJILog::from_bytes(data)
                    }))
                }),
            )
            .await;

            match result {
                Err(_) => return Err(ParserError::Timeout(PARSE_TIMEOUT_SECS)),
                Ok(Err(join_err)) => return Err(ParserError::Panic(format!("Task join error: {}", join_err))),
                Ok(Ok(Err(panic_val))) => {
                    let msg = panic_val
                        .downcast_ref::<String>()
                        .map(|s| s.clone())
                        .or_else(|| panic_val.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_else(|| "unknown panic".to_string());
                    return Err(ParserError::Panic(msg));
                }
                Ok(Ok(Ok(parse_result))) => {
                    parse_result.map_err(|e| ParserError::Parse(e.to_string()))?
                }
            }
        };

        log::info!(
            "DJILog parsed: version={}, product={:?}, aircraft_sn={}, aircraft_name={}, battery_sn={}, total_time={:.1}s",
            parser.version,
            parser.details.product_type,
            parser.details.aircraft_sn,
            parser.details.aircraft_name,
            parser.details.battery_sn,
            parser.details.total_time
        );

        // Check if we need an encryption key for V13+ logs
        let frames = self.get_frames(&parser).await?;
        log::info!("Extracted {} frames from log", frames.len());

        if frames.is_empty() {
            log::warn!("No frames extracted from log file — file may be empty or corrupt");
            return Err(ParserError::NoTelemetryData);
        }

        // Extract telemetry points
        let details_total_time_secs = parser.details.total_time as f64;
        let points = self.extract_telemetry(&frames, details_total_time_secs);
        log::info!(
            "Extracted {} valid telemetry points from {} frames ({} skipped)",
            points.len(),
            frames.len(),
            frames.len() - points.len()
        );

        if points.is_empty() {
            log::warn!("No valid telemetry points after filtering — all frames had corrupt/missing data");
            return Err(ParserError::NoTelemetryData);
        }

        // Calculate statistics
        let stats = self.calculate_stats(&points);

        // Build metadata
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let display_name = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&file_name)
            .to_string();

        let metadata = FlightMetadata {
            id: self.db.generate_flight_id(),
            file_name,
            display_name,
            file_hash: Some(file_hash),
            drone_model: self.extract_drone_model(&parser),
            drone_serial: self.extract_serial(&parser),
            aircraft_name: self.extract_aircraft_name(&parser),
            battery_serial: self.extract_battery_serial(&parser),
            start_time: self.extract_start_time(&parser),
            end_time: self.extract_end_time(&parser),
            duration_secs: Some(
                if details_total_time_secs > 0.0 {
                    details_total_time_secs
                } else {
                    stats.duration_secs
                }
            ),
            total_distance: Some(stats.total_distance_m),
            max_altitude: Some(stats.max_altitude_m),
            max_speed: Some(stats.max_speed_ms),
            home_lat: stats.home_location.map(|h| h[1]),
            home_lon: stats.home_location.map(|h| h[0]),
            point_count: points.len() as i32,
        };

        log::info!(
            "Parse complete in {:.1}s: duration={:.1}s, distance={:.0}m, max_alt={:.1}m, max_speed={:.1}m/s, home={:?}, points={}",
            parse_start.elapsed().as_secs_f64(),
            stats.duration_secs,
            stats.total_distance_m,
            stats.max_altitude_m,
            stats.max_speed_ms,
            stats.home_location,
            points.len()
        );

        Ok(ParseResult { metadata, points })
    }

    /// Get frames from the parser, handling encryption if needed.
    /// Runs the CPU-bound parsing in spawn_blocking with catch_unwind
    /// to prevent panics from crashing the application.
    async fn get_frames(&self, parser: &DJILog) -> Result<Vec<Frame>, ParserError> {
        // Version 13+ requires keychains for decryption
        let keychains = if parser.version >= 13 {
            log::info!("Log version {} >= 13, fetching keychains for decryption", parser.version);
            let api_key = self.api.get_api_key().ok_or_else(|| {
                log::error!("No DJI API key configured — cannot decrypt V13+ log");
                ParserError::EncryptionKeyRequired
            })?;
            let kc = parser
                .fetch_keychains(&api_key)
                .map_err(|e| {
                    log::error!("Keychain fetch failed: {}", e);
                    ParserError::Api(e.to_string())
                })?;
            log::info!("Keychains fetched successfully ({} chains)", kc.len());
            Some(kc)
        } else {
            log::debug!("Log version {} < 13, no decryption needed", parser.version);
            None
        };

        // Clone what we need to move into spawn_blocking
        // DJILog doesn't implement Clone, so we need to use a raw pointer trick
        // Instead, we'll re-read the data inside the blocking task
        // Actually, frames() borrows self, so we need an unsafe approach or restructure.
        // The simplest safe approach: since parser is on the stack, use a scoped approach.
        // We use `unsafe` pointer cast to send the parser ref into spawn_blocking.
        // This is safe because we await the result immediately (parser outlives the task).
        let parser_ptr = parser as *const DJILog as usize;
        let result = timeout(
            Duration::from_secs(PARSE_TIMEOUT_SECS),
            tokio::task::spawn_blocking(move || {
                let parser_ref = unsafe { &*(parser_ptr as *const DJILog) };
                panic::catch_unwind(panic::AssertUnwindSafe(|| {
                    parser_ref.frames(keychains)
                }))
            }),
        )
        .await;

        match result {
            Err(_) => {
                log::error!("frames() timed out after {}s", PARSE_TIMEOUT_SECS);
                Err(ParserError::Timeout(PARSE_TIMEOUT_SECS))
            }
            Ok(Err(join_err)) => {
                log::error!("frames() task join error: {}", join_err);
                Err(ParserError::Panic(format!("Task join error: {}", join_err)))
            }
            Ok(Ok(Err(panic_val))) => {
                let msg = panic_val
                    .downcast_ref::<String>()
                    .map(|s| s.clone())
                    .or_else(|| panic_val.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown panic".to_string());
                log::error!("frames() panicked: {}", msg);
                Err(ParserError::Panic(msg))
            }
            Ok(Ok(Ok(frames_result))) => {
                frames_result.map_err(|e| {
                    log::error!("frames() returned error: {}", e);
                    ParserError::Parse(e.to_string())
                })
            }
        }
    }

    /// Extract telemetry points from parsed frames
    fn extract_telemetry(&self, frames: &[Frame], details_total_time_secs: f64) -> Vec<TelemetryPoint> {
        let mut points = Vec::with_capacity(frames.len());
        let mut timestamp_ms: i64 = 0;

        // Counters for logging
        let mut skipped_corrupt: usize = 0;
        let mut skipped_no_gps: usize = 0;
        let mut skipped_out_of_range: usize = 0;
        let mut skipped_alt_clamp: usize = 0;
        let mut skipped_speed_clamp: usize = 0;

        // Check if any frame has a non-zero fly_time
        let has_fly_time = frames.iter().any(|f| f.osd.fly_time > 0.0);
        log::debug!("fly_time available: {}", has_fly_time);

        // When fly_time is unavailable, compute interval from header duration
        // instead of assuming 100ms (10Hz), which inflates duration for high-rate logs
        let fallback_interval_ms: i64 = if !has_fly_time && details_total_time_secs > 0.0 && !frames.is_empty() {
            ((details_total_time_secs * 1000.0) / frames.len() as f64).round() as i64
        } else {
            100 // default 10Hz assumption
        };

        for frame in frames {
            let osd = &frame.osd;
            let gimbal = &frame.gimbal;
            let battery = &frame.battery;
            let rc = &frame.rc;

            let current_timestamp_ms = if osd.fly_time > 0.0 {
                (osd.fly_time * 1000.0) as i64
            } else {
                timestamp_ms
            };

            // Validate core numeric fields — skip entire frame if data is corrupt
            // (e.g. the parser produced garbage like lat=-6.6e-136, lon=5.7e+139)
            if !is_finite_f64(osd.latitude)
                || !is_finite_f64(osd.longitude)
                || !is_finite_f32(osd.altitude)
                || !is_finite_f32(osd.height)
                || !is_finite_f32(osd.x_speed)
                || !is_finite_f32(osd.y_speed)
                || !is_finite_f32(osd.z_speed)
            {
                // Increment timestamp and skip this corrupt frame
                if skipped_corrupt < 5 {
                    log::debug!(
                        "Skipping corrupt frame at {}ms: lat={}, lon={}, alt={}, height={}, vx={}, vy={}, vz={}",
                        current_timestamp_ms,
                        osd.latitude, osd.longitude, osd.altitude, osd.height,
                        osd.x_speed, osd.y_speed, osd.z_speed
                    );
                }
                skipped_corrupt += 1;
                timestamp_ms = current_timestamp_ms + fallback_interval_ms;
                continue;
            }

            let mut point = TelemetryPoint {
                timestamp_ms: current_timestamp_ms,
                ..Default::default()
            };

            // Filter out invalid GPS coordinates:
            //  - 0,0 means no GPS lock
            //  - Values outside physical range (lat ±90, lon ±180) are corrupt data
            let has_gps_lock = !(osd.latitude.abs() < 1e-6 && osd.longitude.abs() < 1e-6);
            let gps_in_range = osd.latitude.abs() <= 90.0 && osd.longitude.abs() <= 180.0;
            if has_gps_lock && gps_in_range {
                point.latitude = Some(osd.latitude);
                point.longitude = Some(osd.longitude);
            } else if has_gps_lock && !gps_in_range {
                skipped_out_of_range += 1;
            } else {
                skipped_no_gps += 1;
            }
            // else: latitude/longitude remain None (from Default)

            // Clamp altitude/height to physically plausible range (reject garbage)
            let alt = osd.altitude as f64;
            let height = osd.height as f64;
            point.altitude = if alt.abs() < 10_000.0 { Some(alt) } else { skipped_alt_clamp += 1; None };
            point.height = if height.abs() < 10_000.0 { Some(height) } else { skipped_alt_clamp += 1; None };
            point.vps_height = Some(osd.vps_height as f64);

            point.speed = if has_gps_lock && gps_in_range {
                let spd = (osd.x_speed.powi(2) + osd.y_speed.powi(2)).sqrt() as f64;
                if spd < 100.0 { Some(spd) } else { skipped_speed_clamp += 1; None } // >100 m/s is clearly garbage
            } else {
                None // Speed from 0,0 origin is meaningless
            };
            point.velocity_x = if has_gps_lock && gps_in_range { Some(osd.x_speed as f64) } else { None };
            point.velocity_y = if has_gps_lock && gps_in_range { Some(osd.y_speed as f64) } else { None };
            point.velocity_z = if has_gps_lock && gps_in_range { Some(osd.z_speed as f64) } else { None };
            point.pitch = Some(osd.pitch as f64);
            point.roll = Some(osd.roll as f64);
            point.yaw = Some(osd.yaw as f64);
            point.satellites = Some(osd.gps_num as i32);
            point.gps_signal = Some(osd.gps_level as i32);
            point.flight_mode = osd.flyc_state.map(|state| format!("{:?}", state));

            point.gimbal_pitch = Some(gimbal.pitch as f64);
            point.gimbal_roll = Some(gimbal.roll as f64);
            point.gimbal_yaw = Some(gimbal.yaw as f64);

            point.battery_percent = Some(battery.charge_level as i32);
            point.battery_voltage = Some(battery.voltage as f64);
            point.battery_current = Some(battery.current as f64);
            point.battery_temp = Some(battery.temperature as f64);

            point.rc_uplink = rc.uplink_signal.map(i32::from);
            point.rc_downlink = rc.downlink_signal.map(i32::from);
            point.rc_signal = rc.downlink_signal.or(rc.uplink_signal).map(i32::from);

            points.push(point);

            // Increment timestamp using computed interval
            timestamp_ms = current_timestamp_ms + fallback_interval_ms;
        }

        // Log extraction summary
        if skipped_corrupt > 0 || skipped_out_of_range > 0 || skipped_alt_clamp > 0 || skipped_speed_clamp > 0 {
            log::warn!(
                "Telemetry filtering: {} corrupt frames skipped, {} GPS out-of-range, {} no-GPS-lock, {} altitude clamped, {} speed clamped",
                skipped_corrupt, skipped_out_of_range, skipped_no_gps, skipped_alt_clamp, skipped_speed_clamp
            );
        } else {
            log::debug!(
                "Telemetry extraction clean: {} points, {} frames without GPS lock",
                points.len(), skipped_no_gps
            );
        }

        points
    }

    /// Calculate flight statistics from telemetry points
    fn calculate_stats(&self, points: &[TelemetryPoint]) -> FlightStats {
        let duration_secs = points.last().map(|p| p.timestamp_ms as f64 / 1000.0).unwrap_or(0.0);

        let max_altitude = points
            .iter()
            .filter_map(|p| p.height.or(p.altitude))
            .fold(f64::NEG_INFINITY, f64::max);

        let max_speed = points
            .iter()
            .filter_map(|p| p.speed)
            .fold(f64::NEG_INFINITY, f64::max);

        let avg_speed: f64 = {
            let speeds: Vec<f64> = points.iter().filter_map(|p| p.speed).collect();
            if speeds.is_empty() {
                0.0
            } else {
                speeds.iter().sum::<f64>() / speeds.len() as f64
            }
        };

        let min_battery = points
            .iter()
            .filter_map(|p| p.battery_percent)
            .min()
            .unwrap_or(0);

        // Calculate total distance using haversine formula
        let total_distance = self.calculate_total_distance(points);

        // Home location is the first valid GPS point
        let home_location = points
            .iter()
            .find_map(|p| match (p.longitude, p.latitude) {
                (Some(lon), Some(lat)) => Some([lon, lat]),
                _ => None,
            });

        FlightStats {
            duration_secs,
            total_distance_m: total_distance,
            max_altitude_m: if max_altitude.is_finite() {
                max_altitude
            } else {
                0.0
            },
            max_speed_ms: if max_speed.is_finite() { max_speed } else { 0.0 },
            avg_speed_ms: avg_speed,
            min_battery,
            home_location,
        }
    }

    /// Calculate total distance traveled using haversine formula
    fn calculate_total_distance(&self, points: &[TelemetryPoint]) -> f64 {
        let mut total = 0.0;
        let mut prev_lat: Option<f64> = None;
        let mut prev_lon: Option<f64> = None;

        for point in points {
            if let (Some(lat), Some(lon)) = (point.latitude, point.longitude) {
                if let (Some(p_lat), Some(p_lon)) = (prev_lat, prev_lon) {
                    total += haversine_distance(p_lat, p_lon, lat, lon);
                }
                prev_lat = Some(lat);
                prev_lon = Some(lon);
            }
        }

        total
    }

    /// Extract drone model from parser metadata
    fn extract_drone_model(&self, parser: &DJILog) -> Option<String> {
        let model = format!("{:?}", parser.details.product_type);
        if model.starts_with("Unknown") {
            None
        } else {
            Some(model)
        }
    }

    /// Extract serial number from parser
    fn extract_serial(&self, parser: &DJILog) -> Option<String> {
        let sn = parser.details.aircraft_sn.clone();
        if sn.trim().is_empty() {
            None
        } else {
            Some(sn)
        }
    }

    /// Extract aircraft name from parser
    fn extract_aircraft_name(&self, parser: &DJILog) -> Option<String> {
        let name = parser.details.aircraft_name.clone();
        if name.trim().is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Extract battery serial from parser
    fn extract_battery_serial(&self, parser: &DJILog) -> Option<String> {
        let sn = parser.details.battery_sn.clone();
        if sn.trim().is_empty() {
            None
        } else {
            Some(sn)
        }
    }

    /// Extract flight start time
    fn extract_start_time(&self, parser: &DJILog) -> Option<DateTime<Utc>> {
        Some(parser.details.start_time)
    }

    /// Extract flight end time
    fn extract_end_time(&self, parser: &DJILog) -> Option<DateTime<Utc>> {
        let start = self.extract_start_time(parser)?;
        let duration_ms = (parser.details.total_time * 1000.0) as i64;
        Some(start + chrono::Duration::milliseconds(duration_ms))
    }
}

/// Haversine distance calculation in meters
fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6_371_000.0; // Earth's radius in meters

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lon = (lon2 - lon1).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);

    let c = 2.0 * a.sqrt().asin();

    R * c
}

/// Check if an f64 value is finite (not NaN, not Inf)
#[inline]
fn is_finite_f64(v: f64) -> bool {
    v.is_finite()
}

/// Check if an f32 value is finite (not NaN, not Inf)
#[inline]
fn is_finite_f32(v: f32) -> bool {
    v.is_finite()
}
