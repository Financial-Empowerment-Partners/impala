package com.payala.impala;

import android.content.Context;
import android.location.Location;

public class ImpalaGeoHandler {

    public interface GeoUpdateListener {
        void onGeoUpdate(double latitude, double longitude, float accuracy, long timestamp);
    }

    private static GeoUpdateListener listener;

    public static void setGeoUpdateListener(GeoUpdateListener l) {
        listener = l;
    }

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
