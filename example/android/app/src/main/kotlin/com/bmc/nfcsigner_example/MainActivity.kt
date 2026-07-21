package com.bmc.nfcsigner_example

import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import com.bmc.nfcsigner.core.DebugLogger

class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DebugLogger.init(applicationContext)
    }
}
