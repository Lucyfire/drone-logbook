//! DJI Flight Log Viewer - Tauri Backend
//!
//! A high-performance desktop application for analyzing DJI drone flight logs.
//! Built with Tauri v2, DuckDB, and React.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod database;
mod models;
mod parser;

use std::path::PathBuf;
use std::sync::Arc;

use tauri::{AppHandle, Manager, State};
use tauri_plugin_log::{Target, TargetKind};
use log::LevelFilter;

use database::{Database, DatabaseError};
use models::{Flight, FlightDataResponse, ImportResult, OverviewStats, TelemetryData};
use parser::LogParser;
use api::DjiApi;

/// Application state containing the database connection
pub struct AppState {
    pub db: Arc<Database>,
}

/// Get the app data directory for storing the database and logs
fn app_data_dir_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data directory: {}", e))
}

/// Initialize the database in the app data directory
fn init_database(app: &AppHandle) -> Result<Database, String> {
    let data_dir = app_data_dir_path(app)?;
    log::info!("Initializing database in: {:?}", data_dir);

    Database::new(data_dir).map_err(|e| format!("Failed to initialize database: {}", e))
}

// ============================================================================
// TAURI COMMANDS
// ============================================================================

/// Import a DJI flight log file
///
/// This command:
/// 1. Parses the log file (handling V13+ encryption if needed)
/// 2. Bulk inserts telemetry data into DuckDB
/// 3. Returns the new flight ID
#[tauri::command]
async fn import_log(file_path: String, state: State<'_, AppState>) -> Result<ImportResult, String> {
    let import_start = std::time::Instant::now();
    log::info!("Importing log file: {}", file_path);

    let path = PathBuf::from(&file_path);

    if !path.exists() {
        log::warn!("File not found: {}", file_path);
        return Ok(ImportResult {
            success: false,
            flight_id: None,
            message: "File not found".to_string(),
            point_count: 0,
        });
    }

    // Create parser instance
    let parser = LogParser::new(&state.db);

    // Parse the log file
    let parse_result = match parser.parse_log(&path).await {
        Ok(result) => result,
        Err(parser::ParserError::AlreadyImported) => {
            log::info!("Skipping already-imported file: {}", file_path);
            return Ok(ImportResult {
                success: false,
                flight_id: None,
                message: "This flight log has already been imported".to_string(),
                point_count: 0,
            });
        }
        Err(e) => {
            log::error!("Failed to parse log {}: {}", file_path, e);
            return Ok(ImportResult {
                success: false,
                flight_id: None,
                message: format!("Failed to parse log: {}", e),
                point_count: 0,
            });
        }
    };

    // Insert flight metadata
    log::debug!("Inserting flight metadata: id={}", parse_result.metadata.id);
    let flight_id = state
        .db
        .insert_flight(&parse_result.metadata)
        .map_err(|e| format!("Failed to insert flight: {}", e))?;

    // Bulk insert telemetry data — if this fails, clean up the flight metadata
    let point_count = match state
        .db
        .bulk_insert_telemetry(flight_id, &parse_result.points)
    {
        Ok(count) => count,
        Err(e) => {
            log::error!("Failed to insert telemetry for flight {}: {}. Cleaning up.", flight_id, e);
            // Remove the partially inserted flight so it doesn't leave a broken record
            if let Err(cleanup_err) = state.db.delete_flight(flight_id) {
                log::error!("Failed to clean up flight {}: {}", flight_id, cleanup_err);
            }
            return Ok(ImportResult {
                success: false,
                flight_id: None,
                message: format!("Failed to insert telemetry data: {}", e),
                point_count: 0,
            });
        }
    };

    log::info!(
        "Successfully imported flight {} with {} points in {:.1}s",
        flight_id,
        point_count,
        import_start.elapsed().as_secs_f64()
    );

    Ok(ImportResult {
        success: true,
        flight_id: Some(flight_id),
        message: format!(
            "Successfully imported {} telemetry points",
            point_count
        ),
        point_count,
    })
}

/// Get all flights for the sidebar list
#[tauri::command]
async fn get_flights(state: State<'_, AppState>) -> Result<Vec<Flight>, String> {
    let start = std::time::Instant::now();
    let flights = state
        .db
        .get_all_flights()
        .map_err(|e| format!("Failed to get flights: {}", e))?;
    log::debug!("get_flights returned {} flights in {:.1}ms", flights.len(), start.elapsed().as_secs_f64() * 1000.0);
    Ok(flights)
}

/// Get complete flight data for visualization
///
/// This command:
/// 1. Retrieves flight metadata by ID (single row lookup)
/// 2. Fetches telemetry with automatic downsampling for large datasets
/// 3. Returns data optimized for ECharts consumption
#[tauri::command]
async fn get_flight_data(
    flight_id: i64,
    max_points: Option<usize>,
    state: State<'_, AppState>,
) -> Result<FlightDataResponse, String> {
    let start = std::time::Instant::now();
    log::debug!("Fetching flight data for ID: {} (max_points: {:?})", flight_id, max_points);

    // Get flight metadata by ID (single row, not all flights)
    let flight = state
        .db
        .get_flight_by_id(flight_id)
        .map_err(|e| match e {
            DatabaseError::FlightNotFound(id) => format!("Flight {} not found", id),
            _ => format!("Failed to get flight: {}", e),
        })?;

    let known_point_count = flight.point_count.map(|c| c as i64);

    // Get telemetry with automatic downsampling
    let telemetry_records = state
        .db
        .get_flight_telemetry(flight_id, max_points, known_point_count)
        .map_err(|e| match e {
            DatabaseError::FlightNotFound(id) => format!("Flight {} not found", id),
            _ => format!("Failed to get telemetry: {}", e),
        })?;

    // Convert to ECharts-optimized format (single pass)
    let telemetry = TelemetryData::from_records(&telemetry_records);

    // Extract GPS track directly from telemetry data in memory
    // This avoids a second database query entirely
    let track = telemetry.extract_track(2000);

    log::debug!(
        "get_flight_data for flight {} complete in {:.1}ms: {} telemetry series, {} track points",
        flight_id,
        start.elapsed().as_secs_f64() * 1000.0,
        telemetry_records.len(),
        track.len()
    );

    Ok(FlightDataResponse {
        flight,
        telemetry,
        track,
    })
}

/// Get overview stats for all flights
#[tauri::command]
async fn get_overview_stats(state: State<'_, AppState>) -> Result<OverviewStats, String> {
    let start = std::time::Instant::now();
    let stats = state
        .db
        .get_overview_stats()
        .map_err(|e| format!("Failed to get overview stats: {}", e))?;
    log::debug!(
        "get_overview_stats complete in {:.1}ms: {} flights, {:.0}m total distance",
        start.elapsed().as_secs_f64() * 1000.0,
        stats.total_flights,
        stats.total_distance_m
    );
    Ok(stats)
}

/// Delete a flight and all its telemetry data
#[tauri::command]
async fn delete_flight(flight_id: i64, state: State<'_, AppState>) -> Result<bool, String> {
    log::info!("Deleting flight: {}", flight_id);
    state
        .db
        .delete_flight(flight_id)
        .map(|_| true)
        .map_err(|e| format!("Failed to delete flight: {}", e))
}

/// Delete all flights and telemetry
#[tauri::command]
async fn delete_all_flights(state: State<'_, AppState>) -> Result<bool, String> {
    log::warn!("Deleting ALL flights and telemetry");
    state
        .db
        .delete_all_flights()
        .map(|_| true)
        .map_err(|e| format!("Failed to delete all flights: {}", e))
}

/// Update a flight display name
#[tauri::command]
async fn update_flight_name(
    flight_id: i64,
    display_name: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let trimmed = display_name.trim();
    if trimmed.is_empty() {
        return Err("Display name cannot be empty".to_string());
    }

    log::info!("Renaming flight {} to '{}'", flight_id, trimmed);

    state
        .db
        .update_flight_name(flight_id, trimmed)
        .map(|_| true)
        .map_err(|e| format!("Failed to update flight name: {}", e))
}

/// Check if DJI API key is configured
#[tauri::command]
async fn has_api_key(state: State<'_, AppState>) -> Result<bool, String> {
    let api = DjiApi::with_app_data_dir(state.db.data_dir.clone());
    Ok(api.has_api_key())
}

/// Set the DJI API key (saves to config.json in app data directory)
#[tauri::command]
async fn set_api_key(api_key: String, state: State<'_, AppState>) -> Result<bool, String> {
    let api = DjiApi::with_app_data_dir(state.db.data_dir.clone());
    api.save_api_key(&api_key)
        .map(|_| true)
        .map_err(|e| format!("Failed to save API key: {}", e))
}

/// Get the app data directory path
#[tauri::command]
async fn get_app_data_dir(state: State<'_, AppState>) -> Result<String, String> {
    Ok(state.db.data_dir.to_string_lossy().to_string())
}

/// Get the app log directory path
#[tauri::command]
async fn get_app_log_dir(app: AppHandle) -> Result<String, String> {
    app.path()
        .app_log_dir()
        .map_err(|e| format!("Failed to get app log directory: {}", e))
        .map(|dir| dir.to_string_lossy().to_string())
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::new()
                .targets([
                    Target::new(TargetKind::LogDir { file_name: None }),
                    Target::new(TargetKind::Stdout),
                ])
                .level(LevelFilter::Debug)
                .build(),
        )
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .setup(|app| {
            // Initialize database on app startup
            let db = init_database(app.handle())?;

            // Store in app state
            app.manage(AppState { db: Arc::new(db) });

            log::info!("DJI Log Viewer initialized successfully");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            import_log,
            get_flights,
            get_flight_data,
            get_overview_stats,
            delete_flight,
            delete_all_flights,
            update_flight_name,
            has_api_key,
            set_api_key,
            get_app_data_dir,
            get_app_log_dir,
        ])
        .run(tauri::generate_context!())
        .expect("Failed to run DJI Log Viewer");
}

fn main() {
    run();
}
