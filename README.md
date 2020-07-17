# AES-Android
<br/>A library to provide android aes encryption with c++

### Setting up the dependency
<br/>```implementation "com.android.encryption:aes:1.0.0"```

### R8 and ProGuard settings
<br/>```-keepclasseswithmembernames class * {
    native <methods>;
}```

### Feature
<br/>Support AES/ECB AES/CBC AES/CTR encryption

### Key&Iv
<br/>Default key: 935612713@qq.com
<br/>Default iv: my--q--935612713
<br/>You can modify the aes_utils.c file to use your own key and iv

### Result check
<br/>you can check the result at https://www.ssleye.com/aes_cipher.html
