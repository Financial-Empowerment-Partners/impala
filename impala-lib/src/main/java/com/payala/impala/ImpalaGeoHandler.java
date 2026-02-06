package com.payala.impala;

import android.content.Context;
import android.location.Location;

/**
 * Singleton-style handler that dispatches geolocation updates to a registered listener.
 *
 * <p>The application should register a {@link GeoUpdateListener} early in its lifecycle
 * (e.g. in Application.onCreate) so that location events from {@link GeoUpdateReceiver}
 * are not silently dropped.
 *
 * <p>Usage:
 * <pre>
 *   ImpalaGeoHandler.setGeoUpdateListener((lat, lng, accuracy, timestamp) -> {
 *       // Handle location update
 *   });
 * </pre>
 */
public class ImpalaGeoHandler {

    /**
     * Callback interface for receiving geolocation updates.
     */
    public interface GeoUpdateListener {
        /**
         * Called when a new location fix is received.
         *
         * @param latitude  degrees latitude (WGS84)
         * @param longitude degrees longitude (WGS84)
         * @param accuracy  estimated horizontal accuracy in meters
         * @param timestamp UTC time of the fix in milliseconds since epoch
         */
        void onGeoUpdate(double latitude, double longitude, float accuracy, long timestamp);
    }

    private static volatile GeoUpdateListener listener;

    /**
     * Register a listener to receive geolocation updates. Only one listener
     * is supported at a time; setting a new listener replaces the previous one.
     */
    public static void setGeoUpdateListener(GeoUpdateListener l) {
        listener = l;
    }

    /**
     * Dispatch a location update to the registered listener, if any.
     * Called internally by {@link GeoUpdateReceiver}.
     */
    public static void handle_geo_update(Context context, Location location) {
        if (listener != null) {
            listener.onGeoUpdate(
                    location.getLatitude(),
                    location.getLongitude(),
                    location.getAccuracy(),
                    location.getTime()
            );
        }
    }
}
