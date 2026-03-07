package com.example.root_checker

import android.util.Base64

object PackageObfuscator {

    private external fun getPackageKey(): String

    private val encrypted = arrayOf(
        "V1dVG0IrMSwuUFhAQx1aWFNRS14=",
        "UU0WVl4lKCgnUURSGEBCSVFKS0A=",
        "UF0WR1kmN2ggVlJFWVpTF0xIV0ZTIG8vL0tCVlpfUks=",
        "W0pfG1o3MSkyXVIZW1JZWFNdSg==",
        "V1dVG10rNDUpUV1TQ0dDWBpLTUVTNjQ1JEo=",
        "V1dVG1grMi40XllCGFJZXUZXUVEYNzQ=",
        "V1dVG0IsKDQlSFdFQkoZSkFIXUdDNyQ0"
    )

    fun getPackages(): List<String> {
        return encrypted.map { decrypt(it) }
    }

    private fun decrypt(encoded: String): String {
        return try {
            val decoded  = Base64.decode(encoded, Base64.NO_WRAP)
            val keyBytes = getPackageKey().toByteArray()
            val result   = ByteArray(decoded.size) { i ->
                (decoded[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }
            String(result)
        } catch (e: Exception) {
            ""
        }
    }
}