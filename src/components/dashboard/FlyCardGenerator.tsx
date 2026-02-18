/**
 * FlyCard Generator Component
 * Generates a shareable flight stats card similar to Strava's activity cards
 * Uses the current map view as background (captured from FlightMap)
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { formatDuration, formatDistance, formatAltitude, formatSpeed, type UnitSystem } from '@/lib/utils';
import { isWebMode } from '@/lib/api';
import type { Flight } from '@/types';
import logoIcon from '@/assets/icon.png';

// Card dimensions (1080x1080 for social media)
const CARD_WIDTH = 1080;

interface FlyCardGeneratorProps {
  flight: Flight;
  unitSystem: UnitSystem;
  onClose: () => void;
}

/**
 * Async version of map capture with overlay
 */
async function captureMapWithOverlayAsync(): Promise<string | null> {
  const captureFunc = (window as any).__captureFlightMapSnapshot;
  if (!captureFunc) return null;
  
  const snapshot = captureFunc();
  if (!snapshot) return null;
  
  return new Promise<string>((resolve) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        resolve(snapshot);
        return;
      }
      
      // Draw the original map
      ctx.drawImage(img, 0, 0);
      
      // Add dark overlay for text readability
      ctx.fillStyle = 'rgba(0, 0, 0, 0.45)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      resolve(canvas.toDataURL('image/png'));
    };
    img.onerror = () => resolve(snapshot);
    img.src = snapshot;
  });
}

/**
 * Convert HTML element to PNG blob using canvas
 */
async function elementToPng(element: HTMLElement): Promise<Blob> {
  const html2canvas = (await import('html2canvas')).default;
  
  // Get actual element dimensions
  const rect = element.getBoundingClientRect();
  // Calculate scale to get exactly CARD_WIDTH x CARD_HEIGHT output
  const scale = CARD_WIDTH / rect.width;
  
  const canvas = await html2canvas(element, {
    backgroundColor: null,
    scale: scale,
    width: rect.width,
    height: rect.height,
    logging: false,
    useCORS: true,
    allowTaint: true,
  });
  
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) {
        resolve(blob);
      } else {
        reject(new Error('Failed to create blob from canvas'));
      }
    }, 'image/png');
  });
}

/**
 * Download a blob as a file (web mode)
 */
function downloadBlobWeb(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Save blob using Tauri file dialog (desktop mode)
 */
async function saveBlobDesktop(filename: string, blob: Blob): Promise<boolean> {
  try {
    const { save } = await import('@tauri-apps/plugin-dialog');
    const { writeFile } = await import('@tauri-apps/plugin-fs');
    
    const filePath = await save({
      defaultPath: filename,
      filters: [{ name: 'PNG Image', extensions: ['png'] }],
    });
    
    if (!filePath) return false;
    
    const arrayBuffer = await blob.arrayBuffer();
    await writeFile(filePath, new Uint8Array(arrayBuffer));
    return true;
  } catch (err) {
    console.error('Failed to save file:', err);
    return false;
  }
}

export function FlyCardGenerator({ flight, unitSystem, onClose }: FlyCardGeneratorProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [backgroundImage, setBackgroundImage] = useState<string | null>(null);
  const [mapBackground, setMapBackground] = useState<string | null>(null);

  // Capture map background from current FlightMap view on mount
  useEffect(() => {
    let cancelled = false;
    
    async function captureMap() {
      setIsLoading(true);
      try {
        // Wait for map and deck.gl to fully render
        // The flight selection already waited, but give extra time for deck.gl flight path
        await new Promise(resolve => setTimeout(resolve, 300));
        
        if (cancelled) return;
        
        // Capture the current map view
        const mapSnapshot = await captureMapWithOverlayAsync();
        if (!cancelled && mapSnapshot) {
          setMapBackground(mapSnapshot);
        }
      } catch (err) {
        console.error('Failed to capture map:', err);
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }
    
    captureMap();
    return () => { cancelled = true; };
  }, [flight.id]);

  // Handle background image upload (overrides map background)
  const handleImageUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setBackgroundImage(event.target?.result as string);
      };
      reader.readAsDataURL(file);
    }
  }, []);

  // Clear custom background
  const handleClearBackground = useCallback(() => {
    setBackgroundImage(null);
  }, []);

  // Handle export to PNG
  const handleExport = useCallback(async () => {
    if (!cardRef.current) return;
    
    setIsExporting(true);
    try {
      const blob = await elementToPng(cardRef.current);
      const baseName = (flight.displayName || flight.fileName || 'flight').replace(/[^a-zA-Z0-9_\-]/g, '_');
      const fileName = `FlyCard_${baseName}.png`;
      
      if (isWebMode()) {
        downloadBlobWeb(fileName, blob);
      } else {
        await saveBlobDesktop(fileName, blob);
      }
    } catch (err) {
      console.error('Failed to export FlyCard:', err);
    } finally {
      setIsExporting(false);
    }
  }, [flight]);

  // Handle escape key to close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Format stats for display
  const durationValue = formatDuration(flight.durationSecs);
  const distanceFull = formatDistance(flight.totalDistance, unitSystem);
  const maxHeightFull = formatAltitude(flight.maxAltitude, unitSystem);
  const maxSpeedFull = formatSpeed(flight.maxSpeed, unitSystem);
  
  // Aircraft name from flight data or fallback
  const aircraftName = flight.aircraftName || flight.droneModel || 'Unknown Aircraft';

  // Determine which background to use
  const currentBackground = backgroundImage || mapBackground;

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-drone-surface border border-gray-700 rounded-xl p-6 max-w-lg w-full mx-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Generate FlyCard</h2>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded hover:bg-gray-700/50 text-gray-400 hover:text-white transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Background image upload */}
        <div className="mb-4">
          <label className="block text-sm text-gray-400 mb-2">
            Custom Background Image 
            {backgroundImage && (
              <button
                type="button"
                onClick={handleClearBackground}
                className="ml-2 text-xs text-red-400 hover:text-red-300"
              >
                (clear)
              </button>
            )}
          </label>
          <input
            type="file"
            accept="image/*"
            onChange={handleImageUpload}
            className="block w-full text-sm text-gray-400
              file:mr-4 file:py-2 file:px-4
              file:rounded-lg file:border-0
              file:text-sm file:font-medium
              file:bg-drone-primary file:text-white
              hover:file:bg-drone-primary/80
              file:cursor-pointer cursor-pointer"
          />
          {!backgroundImage && mapBackground && (
            <p className="mt-1 text-xs text-gray-500">Using flight map as background</p>
          )}
        </div>

        {/* FlyCard Preview */}
        <div className="mb-4 rounded-lg overflow-hidden border border-gray-600">
          {isLoading ? (
            <div className="w-full aspect-square flex items-center justify-center bg-gray-800">
              <div className="text-center">
                <svg className="w-8 h-8 text-drone-primary animate-spin mx-auto mb-2" fill="none" viewBox="0 0 24 24">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                  <path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="3" strokeLinecap="round" className="opacity-75" />
                </svg>
                <p className="text-sm text-gray-400">Generating map preview...</p>
              </div>
            </div>
          ) : (
            <div
              ref={cardRef}
              className="relative w-full aspect-square"
              style={{
                backgroundImage: currentBackground ? `url(${currentBackground})` : 'none',
                backgroundSize: 'cover',
                backgroundPosition: 'center',
                backgroundColor: currentBackground ? 'transparent' : '#1a1a2e',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
              }}
            >
              {/* Dark overlay for text readability (only if using custom image) */}
              {backgroundImage && (
                <div 
                  className="absolute inset-0"
                  style={{ backgroundColor: 'rgba(0, 0, 0, 0.55)' }}
                />
              )}
              
              {/* Top Center - Branding */}
              <div 
                style={{ 
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  right: 0,
                  textAlign: 'center',
                  padding: '4%',
                }}
              >
                <div
                  style={{
                    display: 'inline-block',
                    verticalAlign: 'middle',
                    width: '22px',
                    height: '22px',
                    borderRadius: '50%',
                    backgroundColor: 'white',
                    boxShadow: '1px 1px 4px rgba(0,0,0,0.5)',
                    marginRight: '8px',
                    position: 'relative',
                  }}
                >
                  <img 
                    src={logoIcon}
                    alt="OpenDroneLog"
                    style={{ 
                      width: '18px',
                      height: '18px',
                      position: 'absolute',
                      top: '2px',
                      left: '2px',
                    }}
                  />
                </div>
                <span 
                  style={{ 
                    display: 'inline-block',
                    verticalAlign: 'middle',
                    color: 'white',
                    fontSize: '11.5px',
                    fontWeight: 500,
                    textShadow: '1px 1px 4px rgba(0,0,0,0.9), 0 0 10px rgba(0,0,0,0.7)',
                    letterSpacing: '0.02em',
                    opacity: 0.9,
                  }}
                >
                  Generated with opendronelog.com
                </span>
              </div>
              
              {/* Bottom Left - Flight Stats */}
              <div 
                className="absolute bottom-0 left-0"
                style={{ padding: '4%' }}
              >
                {/* Aircraft Name */}
                <p 
                  className="text-white mb-2"
                  style={{ 
                    fontSize: '11px',
                    fontWeight: 400,
                    textShadow: '1px 1px 4px rgba(0,0,0,0.9), 0 0 10px rgba(0,0,0,0.7)',
                    letterSpacing: '0.03em',
                    opacity: 0.85,
                  }}
                >
                  {aircraftName}
                </p>

                {/* Stats Grid */}
                <div className="flex flex-col gap-1">
                  {/* Flight Time */}
                  <div>
                    <p 
                      className="text-white uppercase tracking-wider"
                      style={{ 
                        fontSize: '8px',
                        fontWeight: 600,
                        textShadow: '1px 1px 3px rgba(0,0,0,0.9)',
                        letterSpacing: '0.1em',
                        opacity: 0.8,
                      }}
                    >
                      Flight Time
                    </p>
                    <p 
                      className="text-white"
                      style={{ 
                        fontSize: '22px',
                        fontWeight: 800,
                        textShadow: '2px 2px 6px rgba(0,0,0,0.9), 0 0 15px rgba(0,0,0,0.7)',
                        lineHeight: 1.2,
                      }}
                    >
                      {durationValue}
                    </p>
                  </div>

                  {/* Distance */}
                  <div>
                    <p 
                      className="text-white uppercase tracking-wider"
                      style={{ 
                        fontSize: '8px',
                        fontWeight: 600,
                        textShadow: '1px 1px 3px rgba(0,0,0,0.9)',
                        letterSpacing: '0.1em',
                        opacity: 0.8,
                      }}
                    >
                      Distance
                    </p>
                    <p 
                      className="text-white"
                      style={{ 
                        fontSize: '22px',
                        fontWeight: 800,
                        textShadow: '2px 2px 6px rgba(0,0,0,0.9), 0 0 15px rgba(0,0,0,0.7)',
                        lineHeight: 1.2,
                      }}
                    >
                      {distanceFull}
                    </p>
                  </div>

                  {/* Max Height */}
                  <div>
                    <p 
                      className="text-white uppercase tracking-wider"
                      style={{ 
                        fontSize: '8px',
                        fontWeight: 600,
                        textShadow: '1px 1px 3px rgba(0,0,0,0.9)',
                        letterSpacing: '0.1em',
                        opacity: 0.8,
                      }}
                    >
                      Max Height
                    </p>
                    <p 
                      className="text-white"
                      style={{ 
                        fontSize: '22px',
                        fontWeight: 800,
                        textShadow: '2px 2px 6px rgba(0,0,0,0.9), 0 0 15px rgba(0,0,0,0.7)',
                        lineHeight: 1.2,
                      }}
                    >
                      {maxHeightFull}
                    </p>
                  </div>

                  {/* Max Speed */}
                  <div>
                    <p 
                      className="text-white uppercase tracking-wider"
                      style={{ 
                        fontSize: '8px',
                        fontWeight: 600,
                        textShadow: '1px 1px 3px rgba(0,0,0,0.9)',
                        letterSpacing: '0.1em',
                        opacity: 0.8,
                      }}
                    >
                      Max Speed
                    </p>
                    <p 
                      className="text-white"
                      style={{ 
                        fontSize: '22px',
                        fontWeight: 800,
                        textShadow: '2px 2px 6px rgba(0,0,0,0.9), 0 0 15px rgba(0,0,0,0.7)',
                        lineHeight: 1.2,
                      }}
                    >
                      {maxSpeedFull}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex gap-3 justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-700/50 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleExport}
            disabled={isExporting || isLoading}
            className="px-4 py-2 text-sm font-medium text-white bg-drone-primary hover:bg-drone-primary/80 rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            {isExporting ? (
              <>
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                  <path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="3" strokeLinecap="round" className="opacity-75" />
                </svg>
                Saving...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Save as PNG
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
