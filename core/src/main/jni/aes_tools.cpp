//
// Created by CtLoveQy on 2020/7/16.
//

#include <jni.h>
#include <string>
#include "aes_utils.h"
#include "tools.h"
#include "junk.h"
#include "hex_utils.h"

#define JNIREG_CLASS "com/douyu/aes/core/AesUtils"
#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))

#ifdef __cplusplus
extern "C" {
#endif


JNIEXPORT jstring JNICALL method01(JNIEnv *env, jclass jcls, jstring str_) {
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_ECB_PKCS5_Encrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

JNIEXPORT jstring JNICALL method02(JNIEnv *env, jclass jcls, jstring str_) {
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_ECB_PKCS5_Decrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

JNIEXPORT jstring JNICALL method03(JNIEnv *env, jclass jcls, jstring str_) {
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_CBC_PKCS5_Encrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

JNIEXPORT jstring JNICALL method04(JNIEnv *env, jclass jcls, jstring str_) {
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_CBC_PKCS5_Decrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

static JNINativeMethod method_table[] = {
        {"encryptECB", "(Ljava/lang/String;)Ljava/lang/String;", (void *) method01},
        {"decryptECB", "(Ljava/lang/String;)Ljava/lang/String;", (void *) method02},
        {"encryptCBC", "(Ljava/lang/String;)Ljava/lang/String;", (void *) method03},
        {"decryptCBC", "(Ljava/lang/String;)Ljava/lang/String;", (void *) method04}
};

static int registerMethods(JNIEnv *env, const char *className,
                           JNINativeMethod *gMethods, int numMethods) {
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    _JUNK_FUN_0

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    assert(env != nullptr);

    // 注册native方法
    if (!registerMethods(env, JNIREG_CLASS, method_table, NELEM(method_table))) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}


#ifdef __cplusplus
}
#endif