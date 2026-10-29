package org.atlasrf.collector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/** Cross-language vector generated with Python hmac/hashlib; JVM execution pending toolchain. */
class BridgeAuthenticationTest {
    @Test fun signsUtf8WithDomainSeparation() {
        val key = ByteArray(32) { it.toByte() }
        val value = "{\"carrier\":\"Tést\"}"
        assertEquals("c284a780583cad6462a33289e9c604926bada30b23bf7d8aedf690c784c9b456", BridgeAuthentication.sign(key, value))
        assertNotEquals(BridgeAuthentication.sign(key, value), BridgeAuthentication.sign(key, value + " "))
    }
}
