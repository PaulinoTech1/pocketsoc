package org.atlasrf.collector

import org.junit.Assert.*
import org.junit.Test

class ObservationClockTest {
    @Test fun preservesMeasurementRatherThanExportTime() {
        val clock = ObservationClock(1_700_000_000_000, 10_000_000_000)
        val first = clock.utc(11_000_000_000, 12_000_000_000, 1_700_000_002_000)
        val later = clock.utc(11_000_000_000, 15_000_000_000, 1_700_000_005_000)
        assertEquals("2023-11-14T22:13:21Z", first)
        assertEquals(first, later)
    }
    @Test fun rejectsInvalidAndClockJumpedMeasurements() {
        val clock = ObservationClock(1_700_000_000_000, 10_000_000_000)
        assertNull(clock.utc(0, 12_000_000_000, 1_700_000_002_000))
        assertNull(clock.utc(13_000_000_000, 12_000_000_000, 1_700_000_002_000))
        assertNull(clock.utc(11_000_000_000, 12_000_000_000, 1_700_000_020_000))
    }
}
