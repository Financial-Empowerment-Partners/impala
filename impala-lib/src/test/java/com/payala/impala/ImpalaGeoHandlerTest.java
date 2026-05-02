package com.payala.impala;

import android.content.Context;
import android.location.Location;

import androidx.test.core.app.ApplicationProvider;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link ImpalaGeoHandler}.
 *
 * <p>Runs under Robolectric at both the project's {@code minSdk} (24) and
 * {@code targetSdk} (36) so that {@code handle_geo_update} is exercised
 * against the {@link android.location.Location} shadows for both API levels.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = {24, 36})
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
        Context context = ApplicationProvider.getApplicationContext();
        Location location = new Location("test");
        // Should silently log a warning, not throw
        ImpalaGeoHandler.handle_geo_update(context, location);
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

    @Test
    public void handle_geo_update_dispatches_location_fields_to_listener() {
        AtomicReference<double[]> received = new AtomicReference<>();
        ImpalaGeoHandler.setGeoUpdateListener((lat, lng, acc, ts) ->
                received.set(new double[]{lat, lng, acc, ts}));

        Location location = new Location("gps");
        location.setLatitude(37.7749);
        location.setLongitude(-122.4194);
        location.setAccuracy(5.0f);
        location.setTime(1700000000000L);

        Context context = ApplicationProvider.getApplicationContext();
        ImpalaGeoHandler.handle_geo_update(context, location);

        double[] fields = received.get();
        assertNotNull("listener was not invoked", fields);
        assertEquals(37.7749, fields[0], 0.00001);
        assertEquals(-122.4194, fields[1], 0.00001);
        assertEquals(5.0, fields[2], 0.001);
        assertEquals(1700000000000.0, fields[3], 0.0);
    }

    @Test
    public void handle_geo_update_swallows_listener_exception() {
        ImpalaGeoHandler.setGeoUpdateListener((lat, lng, acc, ts) -> {
            throw new RuntimeException("listener boom");
        });

        Context context = ApplicationProvider.getApplicationContext();
        Location location = new Location("gps");
        // Should not propagate the exception
        ImpalaGeoHandler.handle_geo_update(context, location);
    }
}
