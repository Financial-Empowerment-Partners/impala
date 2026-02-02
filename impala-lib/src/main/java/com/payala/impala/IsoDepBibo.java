package com.payala.impala;

import android.nfc.tech.IsoDep;

import com.impala.sdk.apdu4j.BIBO;
import com.impala.sdk.apdu4j.BIBOException;

import java.io.IOException;

/**
 * BIBO implementation backed by an Android IsoDep NFC tag,
 * allowing the ImpalaSDK to transceive APDUs over NFC.
 */
public class IsoDepBibo implements BIBO {

    private final IsoDep isoDep;

    public IsoDepBibo(IsoDep isoDep) {
        this.isoDep = isoDep;
    }

    @Override
    public byte[] transceive(byte[] bytes) throws BIBOException {
        try {
            return isoDep.transceive(bytes);
        } catch (IOException e) {
            throw new BIBOException("NFC transceive failed", e);
        }
    }

    @Override
    public void close() {
        try {
            isoDep.close();
        } catch (IOException ignored) {
        }
    }
}
