package com.example.root_checker

import android.content.Context
import android.content.pm.PackageManager

object SystemIntegrity {
    @JvmStatic
    fun systemIntegrityCheck (context: Context, target: String): Boolean {
        try{
            val packageManager = context.packageManager
            packageManager.getPackageInfo(target, 0)
            return true
        } catch (e: PackageManager.NameNotFoundException) {
            return false
        }   
    }
}