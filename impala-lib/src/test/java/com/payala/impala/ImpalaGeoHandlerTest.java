package com.payala.impala;

import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link ImpalaGeoHandler}.
 */
public class ImpalaGeoHandlerTest {

    @After
    public void tearDown() {
        // Clear any listener set during tests
        ImpalaGeoHandler.setGeoUpdateListener(null);
    }

    @Test
    public void setListener_getListener_returns_same_instance() {
        ImpalaGeoHandler.GeoUpdateListener listener = (lat, lng, acc, ts) -> {};
        ImpalaGeoHandler.setGeoUpdateListener(listener);
        assertSame(listener, ImpalaGeoHandler.getGeoUpdateListener());
    }

    @Test
    public void clearListener_returns_null() {
        ImpalaGeoHandler.GeoUpdateListener listener = (lat, lng, acc, ts) -> {};
        ImpalaGeoHandler.setGeoUpdateListener(listener);
        ImpalaGeoHandler.setGeoUpdateListener(null);
        assertNull(ImpalaGeoHandler.getGeoUpdateListener());
    }

    @Test
    public void null_listener_does_not_crash() {
        // Ensure no exception when no listener registered
        ImpalaGeoHandler.setGeoUpdateListener(null);
        assertNull(ImpalaGeoHandler.getGeoUpdateListener());
        // Cannot call handle_geo_update without android.location.Location on JVM,
        // but verifying the listener state is safe.
    }

    @Test
    public void setListener_replaces_previous() {
        ImpalaGeoHandler.GeoUpdateListener first = (lat, lng, acc, ts) -> {};
        ImpalaGeoHandler.GeoUpdateListener second = (lat, lng, acc, ts) -> {};

        ImpalaGeoHandler.setGeoUpdateListener(first);
        assertSame(first, ImpalaGeoHandler.getGeoUpdateListener());

        ImpalaGeoHandler.setGeoUpdateListener(second);
        assertSame(second, ImpalaGeoHandler.getGeoUpdateListener());
    }
}
