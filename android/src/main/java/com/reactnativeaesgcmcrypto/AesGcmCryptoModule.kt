package com.reactnativeaesgcmcrypto

import com.facebook.react.bridge.*
import com.facebook.react.module.annotations.ReactModule
import java.io.File
import java.security.GeneralSecurityException
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class EncryptionOutput(val iv: ByteArray,
                       val tag: ByteArray,
                       val ciphertext: ByteArray)

@ReactModule(name = "AesGcmCrypto")
class AesGcmCryptoModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
  val GCM_TAG_LENGTH = 16

  override fun getName(): String {
    return "AesGcmCrypto"
  }

  private fun getSecretKeyFromString(key: ByteArray): SecretKey {
    return SecretKeySpec(key, 0, key.size, "AES")
  }

  @Throws(javax.crypto.AEADBadTagException::class)
  fun decryptData(ciphertext: ByteArray, key: ByteArray): ByteArray {
    val secretKey: SecretKey = getSecretKeyFromString(key)
    val ivData = ciphertext.slice(0..11)
    val cipherData = ciphertext.slice(12..ciphertext.size-1);
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, ivData.toByteArray())
    cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
    return cipher.doFinal(cipherData.toByteArray())
  }

  fun encryptData(plainData: ByteArray, key: ByteArray): ByteArray {
    val secretKey: SecretKey = getSecretKeyFromString(key)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val iv = cipher.iv.copyOf()
    val result = cipher.doFinal(plainData)
    //val ciphertext = result.copyOfRange(0, result.size - GCM_TAG_LENGTH)
    //val tag = result.copyOfRange(result.size - GCM_TAG_LENGTH, result.size)
    return Base64.getEncoder().encode(iv + result);
  }

  @ReactMethod
  fun decrypt(base64CipherText: String,
              key: String,
              promise: Promise) {
    try {
      val keyData = Base64.getDecoder().decode(key)
      val ciphertext: ByteArray = Base64.getDecoder().decode(base64CipherText)
      val unsealed: ByteArray = decryptData(ciphertext, keyData)

      promise.resolve(String(unsealed))
    } catch (e: javax.crypto.AEADBadTagException) {
      promise.reject("DecryptionError", "Bad auth tag exception", e)
    } catch (e: GeneralSecurityException) {
      promise.reject("DecryptionError", "Failed to decrypt", e)
    } catch (e: Exception) {
      promise.reject("DecryptionError", "Unexpected error", e)
    }
  }


  @ReactMethod
  fun encrypt(plainText: String,
              inBinary: Boolean,
              key: String,
              promise: Promise) {
    try {
      val keyData = Base64.getDecoder().decode(key)
      val plainData = if (inBinary) Base64.getDecoder().decode(plainText) else plainText.toByteArray(Charsets.UTF_8)
      val sealed = encryptData(plainData, keyData)
      //var response = WritableNativeMap()
      //response.putString("iv", sealed.iv.toHex())
      //response.putString("tag", sealed.tag.toHex())
      //response.putString("content", Base64.getEncoder().encodeToString(sealed.ciphertext))
      promise.resolve(String(sealed))
    } catch (e: GeneralSecurityException) {
      promise.reject("EncryptionError", "Failed to encrypt", e)
    } catch (e: Exception) {
      promise.reject("EncryptionError", "Unexpected error", e)
    }
  }
}
