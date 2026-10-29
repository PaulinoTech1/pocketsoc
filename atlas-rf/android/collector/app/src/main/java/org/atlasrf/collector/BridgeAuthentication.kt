package org.atlasrf.collector

/** Sign exact UTF-8 envelope bytes, including metadata; shared with Debian protocol v1. */
object BridgeAuthentication {
    fun sign(key: ByteArray, signedJson: String): String {
        require(key.size == 32)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(("ATLAS-RF authenticated export v1\n" + signedJson).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
