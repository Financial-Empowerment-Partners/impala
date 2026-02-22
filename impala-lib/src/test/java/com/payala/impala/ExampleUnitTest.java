package com.payala.impala;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for impala-lib components that can run on the host JVM
 * without Android framework dependencies.
 */
public class ExampleUnitTest {

    @Test
    public void geoUpdateReceiver_action_constant() {
        assertEquals(
                "com.payala.impala.ACTION_LOCATION_UPDATE",
                GeoUpdateReceiver.ACTION_LOCATION_UPDATE
        );
    }

    @Test
    public void geoUpdateReceiver_extra_constant() {
        assertEquals("location", GeoUpdateReceiver.EXTRA_LOCATION);
    }

    @Test
    public void geoHandler_null_listener_does_not_throw() {
        // Ensure no NPE when no listener is registered
        ImpalaGeoHandler.setGeoUpdateListener(null);
        assertNull(ImpalaGeoHandler.getGeoUpdateListener());
    }

    @Test
    public void ndefHandler_null_listener_does_not_throw() {
        ImpalaNdefHandler.setNdefListener(null);
        // Verify no exception when clearing the listener
    }

    @Test
    public void geoHandler_listener_can_be_replaced() {
        final int[] callCount = {0};
        ImpalaGeoHandler.GeoUpdateListener listener1 = (lat, lng, acc, ts) -> callCount[0]++;
        ImpalaGeoHandler.GeoUpdateListener listener2 = (lat, lng, acc, ts) -> callCount[0] += 10;

        ImpalaGeoHandler.setGeoUpdateListener(listener1);
        ImpalaGeoHandler.setGeoUpdateListener(listener2);
        // Setting a new listener should replace the old one without error
    }

    @Test
    public void ndefHandler_listener_can_be_replaced() {
        final int[] callCount = {0};
        ImpalaNdefHandler.NdefListener listener1 = messages -> callCount[0]++;
        ImpalaNdefHandler.NdefListener listener2 = messages -> callCount[0] += 10;

        ImpalaNdefHandler.setNdefListener(listener1);
        ImpalaNdefHandler.setNdefListener(listener2);
        // Setting a new listener should replace the old one without error
    }
}
