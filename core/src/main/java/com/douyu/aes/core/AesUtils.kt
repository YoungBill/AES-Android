package com.douyu.aes.core

/**
Created by taochen on 2020/7/16.
Email: 935612713@qq.com.
 */
object AesUtils {
    /**
     * AES加密, ECB, PKCS5Padding
     */
    external fun encryptECB(str: String): String

    /**
     * AES解密, ECB, PKCS5Padding
     */
    external fun decryptECB(str: String): String

    /**
     * AES加密, CBC, PKCS5Padding
     */
    external fun encryptCBC(str: String): String

    /**
     * AES解密, CBC, PKCS5Padding
     */
    external fun decryptCBC(str: String): String

    init {
        System.loadLibrary("Aes")
    }
}