package com.payala.impala;

import android.content.Context;
import android.location.Location;
import android.util.Log;

import java.util.concurrent.atomic.AtomicReference;

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

    private static final String TAG = "ImpalaGeoHandler";

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

    private static final AtomicReference<GeoUpdateListener> listenerRef = new AtomicReference<>();

    /**
     * Register a listener to receive geolocation updates. Only one listener
     * is supported at a time; setting a new listener replaces the previous one.
     */
    public static void setGeoUpdateListener(GeoUpdateListener l) {
        listenerRef.set(l);
    }

    /**
     * Returns the currently registered listener, or null if none.
     */
    public static GeoUpdateListener getGeoUpdateListener() {
        return listenerRef.get();
    }

    /**
     * Dispatch a location update to the registered listener, if any.
     * Called internally by {@link GeoUpdateReceiver}.
     */
    public static void handle_geo_update(Context context, Location location) {
        GeoUpdateListener l = listenerRef.get();
        if (l != null) {
            try {
                l.onGeoUpdate(
                        location.getLatitude(),
                        location.getLongitude(),
                        location.getAccuracy(),
                        location.getTime()
                );
            } catch (Exception e) {
                Log.e(TAG, "Geo callback error: " + e.getMessage());
            }
        } else {
            Log.w(TAG, "No geo listener registered");
        }
    }
}
