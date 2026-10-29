package org.atlasrf.collector

import java.time.Instant

/** Stable per-session conversion; never substitutes export/callback time for measurement time. */
class ObservationClock(val wallMillis: Long, val elapsedNanos: Long) {
    fun utc(measuredNanos: Long, nowElapsed: Long, nowWall: Long): String? {
        if (measuredNanos <= 0 || measuredNanos > nowElapsed) return null
        if (kotlin.math.abs(nowWall - (wallMillis + (nowElapsed - elapsedNanos) / 1_000_000)) > 5000) return null
        return Instant.ofEpochMilli(wallMillis).plusNanos(measuredNanos - elapsedNanos).toString()
    }
}
