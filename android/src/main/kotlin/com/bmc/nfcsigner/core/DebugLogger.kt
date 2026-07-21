package com.bmc.nfcsigner.core

import android.content.Context
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class DebugLogger(private val tag: String) {

    companion object {
        const val DEBUG_USB = true
        private var logFile: File? = null
        private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

        /**
         * Gọi 1 lần khi app khởi động, ví dụ trong onCreate():
         *   DebugLogger.init(applicationContext)
         *
         * Log file: {cacheDir}/ccid_debug.log
         * Lấy file: adb pull /data/data/{package}/cache/ccid_debug.log
         * Hoặc: Share file từ app
         */
        fun init(context: Context) {
            // Dùng external files dir - truy cập được qua file manager
            // Path: /sdcard/Android/data/<package>/files/ccid_debug.log
            val dir = context.getExternalFilesDir(null) ?: context.filesDir
            logFile = File(dir, "ccid_debug.log")
            // Ghi header mỗi lần init (session mới)
            try {
                FileWriter(logFile, true).use { writer ->
                    writer.appendLine("\n===== Session ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())} =====")
                }
            } catch (_: Exception) {}
        }

        /** Trả về nội dung log file (để hiển thị trong UI hoặc share) */
        fun getLogContent(): String {
            return logFile?.takeIf { it.exists() }?.readText() ?: "(no log)"
        }

        /** Xóa log file */
        fun clearLog() {
            logFile?.takeIf { it.exists() }?.delete()
        }

        /** Trả về đường dẫn log file */
        fun getLogFile(): File? = logFile
    }

    fun debug(message: String) {
        if (DEBUG_USB) {
            val timestamp = dateFormat.format(Date())
            val line = "$timestamp [$tag] $message"
            println(line)

            // Ghi ra file
            logFile?.let { file ->
                try {
                    FileWriter(file, true).use { writer ->
                        writer.appendLine(line)
                    }
                } catch (_: Exception) {}
            }
        }
    }
}