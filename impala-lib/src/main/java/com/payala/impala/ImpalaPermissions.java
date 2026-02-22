package com.payala.impala;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

/**
 * Utility class providing permission and hardware availability checks
 * for NFC and location features used by the Impala library.
 */
public class ImpalaPermissions {

    private ImpalaPermissions() {
    }

    /**
     * Check whether the app has been granted {@code ACCESS_FINE_LOCATION} permission.
     */
    public static boolean hasLocationPermission(Context context) {
        return ContextCompat.checkSelfPermission(context,
                Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Check whether NFC hardware is present on this device.
     */
    public static boolean isNfcAvailable(Context context) {
        NfcManager manager = (NfcManager) context.getSystemService(Context.NFC_SERVICE);
        NfcAdapter adapter = manager != null ? manager.getDefaultAdapter() : null;
        return adapter != null;
    }

    /**
     * Check whether NFC hardware is present and currently enabled by the user.
     */
    public static boolean isNfcEnabled(Context context) {
        NfcManager manager = (NfcManager) context.getSystemService(Context.NFC_SERVICE);
        NfcAdapter adapter = manager != null ? manager.getDefaultAdapter() : null;
        return adapter != null && adapter.isEnabled();
    }

    /**
     * Request both fine and coarse location permissions from the user.
     *
     * @param activity    the activity context to use for the permission request
     * @param requestCode the request code to identify this permission request in
     *                    {@code onRequestPermissionsResult}
     */
    public static void requestLocationPermissions(Activity activity, int requestCode) {
        ActivityCompat.requestPermissions(activity,
                new String[]{
                        Manifest.permission.ACCESS_FINE_LOCATION,
                        Manifest.permission.ACCESS_COARSE_LOCATION
                }, requestCode);
    }
}
