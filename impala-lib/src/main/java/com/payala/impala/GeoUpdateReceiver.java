package com.payala.impala;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.location.Location;

/**
 * BroadcastReceiver that listens for geolocation update intents and
 * delegates them to {@link ImpalaGeoHandler} for dispatch to registered listeners.
 *
 * <p>Register this receiver in AndroidManifest.xml with an intent filter for
 * {@link #ACTION_LOCATION_UPDATE}. It is declared as non-exported (internal use only).
 *
 * <p>Location providers (e.g. a foreground service using FusedLocationProviderClient)
 * should broadcast updates using:
 * <pre>
 *   Intent intent = new Intent(GeoUpdateReceiver.ACTION_LOCATION_UPDATE);
 *   intent.putExtra(GeoUpdateReceiver.EXTRA_LOCATION, location);
 *   context.sendBroadcast(intent);
 * </pre>
 */
public class GeoUpdateReceiver extends BroadcastReceiver {

    /** Broadcast action indicating a new location fix is available. */
    public static final String ACTION_LOCATION_UPDATE = "com.payala.impala.ACTION_LOCATION_UPDATE";

    /** Intent extra key for the {@link Location} parcelable payload. */
    public static final String EXTRA_LOCATION = "location";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (ACTION_LOCATION_UPDATE.equals(intent.getAction())) {
            Location location = intent.getParcelableExtra(EXTRA_LOCATION);
            if (location != null) {
                ImpalaGeoHandler.handle_geo_update(context, location);
            }
        }
    }
}
