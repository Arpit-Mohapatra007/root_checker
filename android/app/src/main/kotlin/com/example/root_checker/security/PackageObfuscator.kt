package com.example.root_checker

import android.util.Base64

object PackageObfuscator {

    private external fun getPackageKey(): String

    private val encrypted = arrayOf(
        "IgoKZwcwIAEINz1EFlsfUiwoFgw=",
        "JBBJKhs+OQUBNiFWTQYHQy4zFhI=",
        "IgoKZx0wIwMSOTxGTRQcVzkuDANnACo=",
        "IgoKZxgwJRgPNjhXFgEGUmUyEBcsASojDhU=",
        "IgoKZwc3ORkDLzJBFwxcQD4xABU8ADoi",
        "IgoKZwo6PAcIKDZATQYH",
        "KApJLhorOB4FcTtGEB4LVyxvCAYuGiw7"
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