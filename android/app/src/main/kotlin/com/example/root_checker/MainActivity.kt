package com.example.root_checker

import androidx.annotation.NonNull
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    private val CHANNEL = "com.example.root_checker/security"
    private val URL_CHANNEL = "com.example.root_checker/url"

    companion object {
        init {
            System.loadLibrary("root_checker")
        }
    }

    private external fun nativeCheck(
        nonce: String, isRepackaged: Boolean, isTampered: Boolean,
        isAdb: Boolean, isAccessibility: Boolean, isDev: Boolean, hasMalicious: Boolean
    ): String

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, URL_CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "getUrl") {
                val url = UrlObfuscator.getServerUrl()
                result.success(url)
            } else {
                result.notImplemented()
            }
        }
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "checkRoot") {
                val serverNonce = call.argument<String>("nonce") ?: ""
                if(serverNonce.isEmpty()) {
                    result.error("NO_NONCE", "Server challenge is missing", null)
                    return@setMethodCallHandler
                }

                val isRepackaged = !SystemIntegrity.systemIntegrityCheck(context, "com.example.root_checker")
                val isTampered = SignatureVerifier.signatureCheck(context)
                val isAdb = SettingsCheck.adbEnabled(context)
                val isAccessibility = AccessibilityDetector.isAccessibilityEnabled(context)
                val isDev = SettingsCheck.devOptionsEnabled(context)
                
                val maliciousPackages = PackageObfuscator.getPackages()
                var hasMalicious = false
                for (pkg in maliciousPackages) {
                    if (SystemIntegrity.systemIntegrityCheck(context, pkg)) {
                        hasMalicious = true
                        break
                    }
                }

                val rawResult = nativeCheck(serverNonce, isRepackaged, isTampered, isAdb, isAccessibility, isDev, hasMalicious)
                
                val parts = rawResult.split("|")
                if (parts.size != 2) {
                    result.error("PAYLOAD_ERROR", "Unexpected response format", null)
                    return@setMethodCallHandler
                }

                val hardwareSignature = KeyAttestation.signResult(rawResult)
                val finalResult = mapOf("result" to rawResult, "signature" to hardwareSignature)
                result.success(finalResult)
            } else {
                result.notImplemented()
            }
        }
    }
}