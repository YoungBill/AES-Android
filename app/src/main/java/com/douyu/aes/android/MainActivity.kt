package com.douyu.aes.android

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.douyu.aes.core.AesUtils
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity(), View.OnClickListener {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btn_test_ecb.setOnClickListener(this)
        btn_test_cbc.setOnClickListener(this)
    }

    override fun onClick(v: View) {
        val text = "abc_-=.,123~!@#$%^&*()_+"
        when (v.id) {
            R.id.btn_test_ecb -> {
                val textEncEcb: String = AesUtils.encryptECB(text)
                val textDecEcb: String = AesUtils.decryptECB(textEncEcb)
                Log.d("aes", "text: $text")
                Log.d("aes", "text encryptECB: $textEncEcb")
                Log.d("aes", "text decryptECB: $textDecEcb")
            }
            R.id.btn_test_cbc -> {
                val textEnc: String = AesUtils.encryptCBC(text)
                val textDec: String = AesUtils.decryptCBC(textEnc)
                Log.d("aes", "text: $text")
                Log.d("aes", "text encryptCBC: $textEnc")
                Log.d("aes", "text decryptCBC: $textDec")
            }
        }
        Log.d("aes", "you can check the result at https://www.ssleye.com/aes_cipher.html")
        Toast.makeText(this, "see result at logcat", Toast.LENGTH_SHORT).show()
    }
}