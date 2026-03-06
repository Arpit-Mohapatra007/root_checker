package com.example.root_checker

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import java.security.MessageDigest

object SignatureVerifier {

    private external fun getXorKey(): String

    private const val h = "cQBWK0E5NgpROjIKARARCi51Bld/QWtlWl5uZQdbERMCKSUDV3wXPjIMVW9gA1JGRAF5JV1XLUFnMQwBOmoHVQ=="
    
    private fun decrypt(): String {
        return try {
            val d        = Base64.decode(h, Base64.NO_WRAP)
            val keyBytes = getXorKey().toByteArray()
            val result   = ByteArray(d.size) { i ->
                (d[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }
            String(result)
        } catch (e: Exception) {
            ""
        }
    }

    @JvmStatic
    @Suppress("DEPRECATION")
    fun signatureCheck(context: Context): Boolean {
        try {
            val packageManager = context.packageManager
            val packageName    = context.packageName
            val signatures: Array<out android.content.pm.Signature>?

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = packageInfo.signingInfo ?: return true
                signatures = if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            } else {
                val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                signatures = packageInfo.signatures
            }

            if (signatures.isNullOrEmpty()) return true

            val currentHash = MessageDigest.getInstance("SHA-256")
                .digest(signatures[0].toByteArray())
                .joinToString("") { "%02x".format(it) }

            return !decrypt().equals(currentHash, ignoreCase = true)

        } catch (e: Exception) {
            return true
        }
    }
}