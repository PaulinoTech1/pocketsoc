package org.atlasrf.collector

/** Null means default-manager radio scope, never a made-up subscription ID. */
object CellularTargets {
    fun select(activeIds: List<Int>): List<Int?> {
        val ids = activeIds.filter { it >= 0 }.distinct().take(8)
        return if (ids.isEmpty()) listOf(null) else ids
    }
}
