package com.example.root_checker

import android.util.Base64

object UrlObfuscator {

    private external fun getUrlKey(): String

    private const val encrypted = "KRETOQBlel0eMDxHThYaVigqABVkET42GQkxNx0MGwBWJSUAFWcQMDg="

    fun getServerUrl(): String {
        return try {
            val decoded  = Base64.decode(encrypted, Base64.NO_WRAP)
            val keyBytes = getUrlKey().toByteArray()
            val result   = ByteArray(decoded.size) { i ->
                (decoded[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }
            String(result)
        } catch (e: Exception) {
            ""
        }
    }
}