/**
 * Zustand store for flight state management
 * Manages the currently selected flight and flight list
 */

import { create } from 'zustand';
import * as api from '@/lib/api';
import type { Flight, FlightDataResponse, ImportResult, OverviewStats } from '@/types';

interface FlightState {
  // State
  flights: Flight[];
  selectedFlightId: number | null;
  currentFlightData: FlightDataResponse | null;
  overviewStats: OverviewStats | null;
  isLoading: boolean;
  isImporting: boolean;
  error: string | null;
  unitSystem: 'metric' | 'imperial';
  themeMode: 'system' | 'dark' | 'light';
  donationAcknowledged: boolean;

  // Flight data cache (keyed by flight ID)
  _flightDataCache: Map<number, FlightDataResponse>;

  // Actions
  loadFlights: () => Promise<void>;
  loadOverview: () => Promise<void>;
  selectFlight: (flightId: number) => Promise<void>;
  importLog: (fileOrPath: string | File) => Promise<ImportResult>;
  deleteFlight: (flightId: number) => Promise<void>;
  updateFlightName: (flightId: number, displayName: string) => Promise<void>;
  setUnitSystem: (unitSystem: 'metric' | 'imperial') => void;
  setThemeMode: (themeMode: 'system' | 'dark' | 'light') => void;
  setDonationAcknowledged: (value: boolean) => void;
  clearSelection: () => void;
  clearError: () => void;
}

export const useFlightStore = create<FlightState>((set, get) => ({
  // Initial state
  flights: [],
  selectedFlightId: null,
  currentFlightData: null,
  overviewStats: null,
  isLoading: false,
  isImporting: false,
  error: null,
  unitSystem:
    (typeof localStorage !== 'undefined' &&
      (localStorage.getItem('unitSystem') as 'metric' | 'imperial')) ||
    'metric',
  themeMode: (() => {
    if (typeof localStorage === 'undefined') return 'system';
    const stored = localStorage.getItem('themeMode');
    return stored === 'dark' || stored === 'light' || stored === 'system'
      ? stored
      : 'system';
  })(),
  donationAcknowledged:
    typeof localStorage !== 'undefined'
      ? localStorage.getItem('donationAcknowledged') === 'true'
      : false,
  _flightDataCache: new Map(),

  // Load all flights from database
  loadFlights: async () => {
    set({ isLoading: true, error: null });
    try {
      const flights = await api.getFlights();
      set({ flights, isLoading: false });

      // Auto-select last used flight if available (avoid heavy load on fresh startup)
      const selectedFlightId = get().selectedFlightId;
      if (flights.length > 0 && selectedFlightId === null) {
        const lastSelectedRaw =
          typeof localStorage !== 'undefined'
            ? localStorage.getItem('lastSelectedFlightId')
            : null;
        const lastSelectedId = lastSelectedRaw ? Number(lastSelectedRaw) : null;
        if (lastSelectedId && flights.some((flight) => flight.id === lastSelectedId)) {
          try {
            await get().selectFlight(lastSelectedId);
          } catch {
            // If auto-select fails on startup, clear the persisted ID so we don't crash-loop
            console.warn('Auto-select of last flight failed, clearing lastSelectedFlightId');
            if (typeof localStorage !== 'undefined') {
              localStorage.removeItem('lastSelectedFlightId');
            }
            set({ selectedFlightId: null, currentFlightData: null, isLoading: false, error: null });
          }
        }
      }
    } catch (err) {
      set({ 
        isLoading: false, 
        error: `Failed to load flights: ${err}` 
      });
    }
  },

  loadOverview: async () => {
    set({ isLoading: true, error: null });
    try {
      const stats = await api.getOverviewStats();
      set({ overviewStats: stats, isLoading: false });
    } catch (err) {
      set({
        isLoading: false,
        error: `Failed to load overview stats: ${err}`,
      });
    }
  },

  // Select a flight and load its data (with cache)
  selectFlight: async (flightId: number) => {
    // Skip if already selected
    if (get().selectedFlightId === flightId && get().currentFlightData) {
      return;
    }

    // Always show loading briefly so user sees click feedback
    set({ isLoading: true, error: null, selectedFlightId: flightId, currentFlightData: null });

    // Check cache first
    const cached = get()._flightDataCache.get(flightId);
    if (cached) {
      // Brief delay so spinner is visible even on cache hit
      await new Promise((resolve) => setTimeout(resolve, 120));
      set({ currentFlightData: cached, isLoading: false, error: null });
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('lastSelectedFlightId', String(flightId));
      }
      return;
    }
    try {
      const flightData = await api.getFlightData(flightId, 5000);

      // Store in cache (limit cache size to 10 entries)
      const cache = new Map(get()._flightDataCache);
      if (cache.size >= 10) {
        const firstKey = cache.keys().next().value;
        if (firstKey !== undefined) cache.delete(firstKey);
      }
      cache.set(flightId, flightData);

      set({ currentFlightData: flightData, isLoading: false, _flightDataCache: cache });
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('lastSelectedFlightId', String(flightId));
      }
    } catch (err) {
      // Clear the persisted flight ID on error so we don't crash-loop on restart
      if (typeof localStorage !== 'undefined') {
        localStorage.removeItem('lastSelectedFlightId');
      }
      set({ 
        isLoading: false, 
        selectedFlightId: null,
        currentFlightData: null,
        error: `Failed to load flight data: ${err}` 
      });
    }
  },

  // Import a new log file
  importLog: async (fileOrPath: string | File) => {
    set({ isImporting: true, error: null });
    try {
      const result = await api.importLog(fileOrPath);
      
      if (result.success && result.flightId) {
        // Reload flights and select the new one
        await get().loadFlights();
        await get().selectFlight(result.flightId);
      }
      
      set({ isImporting: false });
      return result;
    } catch (err) {
      const errorMessage = `Import failed: ${err}`;
      set({ isImporting: false, error: errorMessage });
      return {
        success: false,
        flightId: null,
        message: errorMessage,
        pointCount: 0,
      };
    }
  },

  // Delete a flight
  deleteFlight: async (flightId: number) => {
    try {
      await api.deleteFlight(flightId);
      
      // Remove from cache
      const cache = new Map(get()._flightDataCache);
      cache.delete(flightId);
      
      // Clear selection if deleted flight was selected
      if (get().selectedFlightId === flightId) {
        set({ selectedFlightId: null, currentFlightData: null, _flightDataCache: cache });
      } else {
        set({ _flightDataCache: cache });
      }
      
      // Reload flights
      await get().loadFlights();
    } catch (err) {
      set({ error: `Failed to delete flight: ${err}` });
    }
  },

  // Update flight display name
  updateFlightName: async (flightId: number, displayName: string) => {
    try {
      await api.updateFlightName(flightId, displayName);

      // Update local list
      const flights = get().flights.map((flight) =>
        flight.id === flightId
          ? { ...flight, displayName }
          : flight
      );
      set({ flights });

      // If selected, update current flight data too
      const current = get().currentFlightData;
      if (current && current.flight.id === flightId) {
        const updated = {
          ...current,
          flight: { ...current.flight, displayName },
        };
        // Update cache too
        const cache = new Map(get()._flightDataCache);
        cache.set(flightId, updated);
        set({
          currentFlightData: updated,
          _flightDataCache: cache,
        });
      }
    } catch (err) {
      set({ error: `Failed to update flight name: ${err}` });
    }
  },

  setUnitSystem: (unitSystem) => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('unitSystem', unitSystem);
    }
    set({ unitSystem });
  },

  setThemeMode: (themeMode) => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('themeMode', themeMode);
    }
    set({ themeMode });
  },

  setDonationAcknowledged: (value) => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('donationAcknowledged', String(value));
    }
    set({ donationAcknowledged: value });
  },

  clearSelection: () =>
    set({
      selectedFlightId: null,
      currentFlightData: null,
      overviewStats: null,
    }),

  // Clear error
  clearError: () => set({ error: null }),
}));
