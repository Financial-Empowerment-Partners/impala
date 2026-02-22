package com.payala.impala;

import android.nfc.tech.IsoDep;
import android.util.Log;

import com.impala.sdk.apdu4j.BIBO;
import com.impala.sdk.apdu4j.BIBOException;

import java.io.IOException;

/**
 * BIBO implementation backed by an Android IsoDep NFC tag,
 * allowing the ImpalaSDK to transceive APDUs over NFC.
 */
public class IsoDepBibo implements BIBO {

    private static final String TAG = "ImpalaIsoDepBibo";
    private static final int DEFAULT_TIMEOUT_MS = 5000;

    private final IsoDep isoDep;

    public IsoDepBibo(IsoDep isoDep) {
        this(isoDep, DEFAULT_TIMEOUT_MS);
    }

    public IsoDepBibo(IsoDep isoDep, int timeoutMs) {
        this.isoDep = isoDep;
        isoDep.setTimeout(timeoutMs);
    }

    @Override
    public byte[] transceive(byte[] bytes) throws BIBOException {
        try {
            return isoDep.transceive(bytes);
        } catch (IOException e) {
            Log.e(TAG, "Transceive failed: " + e.getMessage());
            throw new BIBOException("NFC transceive failed", e);
        }
    }

    @Override
    public void close() {
        try {
            isoDep.close();
        } catch (IOException e) {
            Log.e(TAG, "Close failed: " + e.getMessage());
        }
    }
}
