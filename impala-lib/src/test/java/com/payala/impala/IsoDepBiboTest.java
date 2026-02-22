package com.payala.impala;

import android.nfc.tech.IsoDep;

import com.impala.sdk.apdu4j.BIBOException;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link IsoDepBibo}.
 */
public class IsoDepBiboTest {

    private IsoDep mockIsoDep;

    @Before
    public void setUp() {
        mockIsoDep = mock(IsoDep.class);
    }

    @Test
    public void transmit_delegates_to_isoDep_transceive() throws Exception {
        byte[] command = new byte[]{0x00, (byte) 0xA4, 0x04, 0x00};
        byte[] expected = new byte[]{(byte) 0x90, 0x00};
        when(mockIsoDep.transceive(command)).thenReturn(expected);

        IsoDepBibo bibo = new IsoDepBibo(mockIsoDep);
        byte[] result = bibo.transceive(command);

        assertArrayEquals(expected, result);
        verify(mockIsoDep).transceive(command);
    }

    @Test(expected = BIBOException.class)
    public void transmit_wraps_ioException_in_biboException() throws Exception {
        when(mockIsoDep.transceive(any(byte[].class))).thenThrow(new IOException("NFC error"));

        IsoDepBibo bibo = new IsoDepBibo(mockIsoDep);
        bibo.transceive(new byte[]{0x00});
    }

    @Test
    public void close_handles_ioException_gracefully() throws Exception {
        doThrow(new IOException("Close error")).when(mockIsoDep).close();

        IsoDepBibo bibo = new IsoDepBibo(mockIsoDep);
        // Should not throw
        bibo.close();

        verify(mockIsoDep).close();
    }

    @Test
    public void default_constructor_sets_timeout() {
        IsoDepBibo bibo = new IsoDepBibo(mockIsoDep);
        verify(mockIsoDep).setTimeout(5000);
    }

    @Test
    public void custom_timeout_constructor_sets_timeout() {
        IsoDepBibo bibo = new IsoDepBibo(mockIsoDep, 10000);
        verify(mockIsoDep).setTimeout(10000);
    }
}
