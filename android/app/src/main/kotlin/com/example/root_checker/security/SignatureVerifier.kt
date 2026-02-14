package com.example.root_checker

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest
import android.util.Base64

object SignatureVerifier{
    private const val h = "ZSxQKh8IMgRpLBR4LC0QHxZ/AFtxC1llDgt8W2VVVlVkLx0hWGUTFSsHAEgDe3ltDxNcQGhhU3Z0QycuJUNgVA=="
    private const val k = BuildConfig.XOR_KEY
    private fun decrypt(): String{
        return try {
            val d = Base64.decode(h,Base64.NO_WRAP)
            val key = k.toByteArray()
            val decrypted = ByteArray(d.size)

            for (i in d.indices){
                decrypted[i] = (d[i].toInt() xor key[i % key.size].toInt()).toByte()
            }
            String(decrypted)
        } catch (e: Exception) {
            ""
        }
    }
    @JvmStatic
    fun signatureCheck(context: Context): Boolean {
        try {
            val packageManager = context.packageManager
            val packageName = context.packageName
            val flags = PackageManager.GET_SIGNATURES
            val packageInfo = packageManager.getPackageInfo(packageName, flags)
            val signatures = packageInfo.signatures
            if (signatures == null){
                return true
            }
            val md = MessageDigest.getInstance("SHA-256")
            val currentHash = md.digest(signatures[0].toByteArray()).joinToString("") { "%02x".format(it) }
            val validHash = decrypt()
            return !validHash.equals(currentHash,ignoreCase = true)
        }
        catch(e:Exception) {
            return true
        }
    }
}