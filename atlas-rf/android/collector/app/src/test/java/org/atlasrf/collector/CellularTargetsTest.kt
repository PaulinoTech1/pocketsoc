package org.atlasrf.collector

import org.junit.Assert.assertEquals
import org.junit.Test

class CellularTargetsTest {
    @Test fun emptySubscriptionsStillAttemptDefaultRadio() {
        assertEquals(listOf<Int?>(null), CellularTargets.select(emptyList()))
        assertEquals(listOf<Int?>(null), CellularTargets.select(listOf(-1)))
    }
    @Test fun realSubscriptionZeroIsNotDefaultRadio() {
        assertEquals(listOf<Int?>(0, 4), CellularTargets.select(listOf(0, 4, 4, -1)))
        assertEquals(8, CellularTargets.select((0..20).toList()).size)
    }
}
