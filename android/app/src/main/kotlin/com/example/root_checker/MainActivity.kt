package com.example.root_checker

import androidx.annotation.NonNull
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    private val CHANNEL = "com.example.root_checker/security"

    companion object {
        init {
            System.loadLibrary("root_checker")
        }
    }

    private external fun nativeCheck(): Int

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "checkRoot") {
                var errorCode = nativeCheck()
                if (!SystemIntegrity.systemIntegrityCheck(context, "com.example.root_checker")){
                    if (errorCode == 0 || errorCode >= 400) {
                        errorCode = 314
                    }
                }
                if (KeyAttestation.checkKeyAttestation("root_check_challenge")) {
                     if (errorCode == 0 || errorCode >= 400) {
                        errorCode = 315
                    }
                }
                // if (SignatureVerifier.signatureCheck(context)) {
                    //    if (errorCode == 0 || errorCode >= 400) {
                    //     errorCode = 316
                    // }
                // }
                if (errorCode == 0) {
                    if (SettingsCheck.adbEnabled(context)){
                        errorCode = 407
                    }
                    else if (AccessibilityDetector.isAccessibilityEnabled(context)){
                        errorCode = 408
                    }
                    else if (SettingsCheck.devOptionsEnabled(context)) {
                        errorCode = 409
                    }
                }
                result.success(errorCode)
            } else {
                result.notImplemented()
            }
        }
    }
}