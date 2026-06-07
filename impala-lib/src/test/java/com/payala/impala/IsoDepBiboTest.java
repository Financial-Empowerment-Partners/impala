package com.payala.impala;

import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;

import com.impala.sdk.apdu4j.BIBOException;

import org.junit.Before;
import org.junit.Test;

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

    @Test
    public void tagLost_is_mapped_to_biboException() throws Exception {
        when(mockIsoDep.transceive(any(byte[].class)))
                .thenThrow(new TagLostException("card removed"));

        IsoDepBibo bibo = new IsoDepBibo(mockIsoDep);
        try {
            bibo.transceive(new byte[]{0x00});
            fail("Expected BIBOException");
        } catch (BIBOException e) {
            assertTrue("message should mention tag loss",
                    e.getMessage() != null && e.getMessage().toLowerCase().contains("lost"));
        }
    }

    @Test
    public void oversized_apdu_is_rejected_before_transceive() throws Exception {
        when(mockIsoDep.getMaxTransceiveLength()).thenReturn(10);
        when(mockIsoDep.isExtendedLengthApduSupported()).thenReturn(false);

        IsoDepBibo bibo = new IsoDepBibo(mockIsoDep);
        try {
            bibo.transceive(new byte[20]);
            fail("Expected BIBOException for oversized APDU");
        } catch (BIBOException e) {
            assertTrue(e.getMessage() != null && e.getMessage().contains("exceeds"));
        }
        // The oversized command must never reach the card.
        verify(mockIsoDep, never()).transceive(any(byte[].class));
    }

    @Test
    public void apdu_within_max_length_is_transmitted() throws Exception {
        byte[] command = new byte[]{0x00, (byte) 0xA4, 0x04, 0x00};
        byte[] expected = new byte[]{(byte) 0x90, 0x00};
        when(mockIsoDep.getMaxTransceiveLength()).thenReturn(261);
        when(mockIsoDep.transceive(command)).thenReturn(expected);

        IsoDepBibo bibo = new IsoDepBibo(mockIsoDep);
        assertArrayEquals(expected, bibo.transceive(command));
    }
}
