package com.bmc.nfcsigner.nfc

import android.nfc.Tag
import android.nfc.tech.IsoDep
import com.bmc.nfcsigner.core.CardOperationManager
import com.bmc.nfcsigner.core.Transceiver
import java.io.IOException

class NfcCardManager {

    private var transceiver: Transceiver? = null
    private var cardOperationManager: CardOperationManager? = null

    fun initialize(tag: Tag): Boolean {
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            return false
        }

        transceiver = NfcTransceiver(isoDep)
        cardOperationManager = CardOperationManager(transceiver!!)
        return true
    }

    fun getCardOperationManager(): CardOperationManager {
        return cardOperationManager ?: throw IllegalStateException("NFC card manager not initialized")
    }

    fun disconnect() {
        transceiver?.disconnect()
        transceiver = null
        cardOperationManager = null
    }

    @Throws(IOException::class)
    fun executeWithNfcCard(tag: Tag, block: (CardOperationManager) -> Unit): Boolean {
        if (!initialize(tag)) {
            return false
        }

        try {
            block(getCardOperationManager())
            return true
        } finally {
            disconnect()
        }
    }
}