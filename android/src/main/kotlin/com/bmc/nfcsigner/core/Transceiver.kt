package com.bmc.nfcsigner.core

import com.bmc.nfcsigner.models.ApduResponse
import java.io.IOException

interface Transceiver {
    @Throws(IOException::class)
    fun transceive(command: ByteArray): ApduResponse

    fun connect()
    fun disconnect()
    fun isConnected(): Boolean
}