package com.example.root_checker

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest

object SignatureVerifier{
    private val validHash = ""
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
            return !validHash.contentEquals(currentHash)
        }
        catch(e:Exception) {
            return true
        }
    }
}