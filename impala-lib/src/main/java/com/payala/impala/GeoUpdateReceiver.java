package com.payala.impala;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.location.Location;

public class GeoUpdateReceiver extends BroadcastReceiver {

    public static final String ACTION_LOCATION_UPDATE = "com.payala.impala.ACTION_LOCATION_UPDATE";
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
