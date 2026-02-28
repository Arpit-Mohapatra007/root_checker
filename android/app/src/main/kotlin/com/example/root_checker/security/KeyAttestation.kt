package com.example.root_checker

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.KeyPairGenerator
import android.util.Base64
import java.util.UUID
object KeyAttestation {
    @JvmStatic
    fun signResult(cxxResult: String): String
{
    val keyAlias = UUID.randomUUID().toString()

    try{
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(cxxResult.toByteArray())
            .build()

        kpg.initialize(spec)
        kpg.generateKeyPair()

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val certificates = keyStore.getCertificateChain(keyAlias)

        if(certificates != null && certificates.isNotEmpty()){
            val attestation = certificates[0].encoded
            keyStore.deleteEntry(keyAlias)
            return Base64.encodeToString(attestation, Base64.NO_WRAP)
        }
        return "ATTESTATION_FAILED"
    }catch (e: Exception){
        return "ATTESTATION_FAILED"
    }
}
}