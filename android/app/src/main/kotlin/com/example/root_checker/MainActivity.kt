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

    private external fun nativeCheck(nonce: String): String

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "checkRoot") {
                val serverNonce = call.argument<String>("nonce") ?: ""
                if(serverNonce.isEmpty()) {
                    result.error("NO_NONCE", "Server challenge is missing", null)
                    return@setMethodCallHandler
                }
                val rawResult = nativeCheck(serverNonce)
                val parts = rawResult.split("|")
                if (parts.size != 2) {
                    result.error("PAYLOAD_ERROR", "Unexpected response format", null)
                    return@setMethodCallHandler
                }
                val hash = parts[0]
                var errorCode = parts[1].toIntOrNull()?:999
                if (!SystemIntegrity.systemIntegrityCheck(context, "com.example.root_checker")){
                    if (errorCode == 0 || errorCode >= 400) {
                        errorCode = 314
                    }
                }
                
                if (SignatureVerifier.signatureCheck(context)) {
                       if (errorCode == 0 || errorCode >= 400) {
                        errorCode = 316
                    }
                }
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
                val finalPayload = "$hash|$errorCode"
                val hardwareSignature = KeyAttestation.signResult(finalPayload)
                val finalResult = mapOf("result" to finalPayload, "signature" to hardwareSignature)
                result.success(finalResult)
            } else {
                result.notImplemented()
            }
        }
    }
}