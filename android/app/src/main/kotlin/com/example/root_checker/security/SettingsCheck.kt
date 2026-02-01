package com.example.root_checker

import android.content.Context
import android.provider.Settings

object SettingsCheck {
    @JvmStatic
    fun adbEnabled(context: Context): Boolean {
        return try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        }
        catch(e: Exception) {
            false
        }
    }

    @JvmStatic
    fun devOptionsEnabled(context: Context): Boolean {
        return try{
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        }
        catch(e: Exception) {
            false
        }
    }
}