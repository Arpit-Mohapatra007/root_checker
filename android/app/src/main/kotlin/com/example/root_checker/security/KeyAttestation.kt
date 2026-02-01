package com.example.root_checker

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.KeyPairGenerator
import java.util.Base64

object KeyAttestation {
    @JvmStatic
    fun checkKeyAttestation(challenge: String): Boolean {
        val keyAlias = "attestation_key"
        try {
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )

            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge.toByteArray())
                .build()

            kpg.initialize(spec)
            kpg.generateKeyPair()

            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            val certificates = keyStore.getCertificateChain(keyAlias)

            return !(certificates != null && certificates.isNotEmpty())
        } catch (e: Exception) {
            return false
        }
    }
}