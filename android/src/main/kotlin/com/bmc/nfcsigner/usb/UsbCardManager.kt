package com.bmc.nfcsigner.usb

import com.bmc.nfcsigner.core.CardOperationManager
import com.bmc.nfcsigner.core.DebugLogger
import com.bmc.nfcsigner.core.Transceiver
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import java.io.IOException

class UsbCardManager(private val usbDeviceManager: UsbDeviceManager) {

    private val logger = DebugLogger("UsbCardManager")
    private var transceiver: UsbTransceiver? = null
    private var cardOperationManager: CardOperationManager? = null

    companion object {
        // Số lần retry tối đa khi ICC Power On trả ATR rỗng
        private const val MAX_POWER_ON_RETRIES: Int = 1
    }

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        if (!usbDeviceManager.connect()) {
            logger.debug("USB device connection failed")
            return@withContext false
        }

        val usbTransceiver = usbDeviceManager.createTransceiver()
        if (usbTransceiver == null) {
            logger.debug("Failed to create USB transceiver")
            return@withContext false
        }

        // ICC Power On — kích hoạt card slot trước khi gửi APDU
        // resetPipeState() được gọi bên trong iccPowerOn() để clear stale data
        try {
            var atr = usbTransceiver.iccPowerOn()
            logger.debug("Card activated, ATR length: ${atr.size}")

            // Nếu ATR rỗng trên composite device, thử power off → reconnect → power on lại
            if (atr.isEmpty()) {
                logger.debug("Empty ATR received, retrying with full reconnect...")

                for (retry in 1..MAX_POWER_ON_RETRIES) {
                    logger.debug("Power On retry $retry/$MAX_POWER_ON_RETRIES")

                    // Power off card slot
                    try {
                        usbTransceiver.iccPowerOff()
                    } catch (e: Exception) {
                        logger.debug("ICC Power Off during retry failed (non-fatal): ${e.message}")
                    }

                    // Đợi một chút để card reset
                    Thread.sleep(200)

                    // Retry power on
                    atr = usbTransceiver.iccPowerOn()
                    logger.debug("Retry $retry ATR length: ${atr.size}")

                    if (atr.isNotEmpty()) {
                        break
                    }
                }

                if (atr.isEmpty()) {
                    logger.debug("ATR still empty after $MAX_POWER_ON_RETRIES retries")
                    // Vẫn tiếp tục — một số reader composite trả ATR rỗng nhưng vẫn hoạt động
                }
            }
        } catch (e: Exception) {
            logger.debug("ICC Power On failed: ${e.message}")
            usbDeviceManager.disconnect()
            return@withContext false
        }

        transceiver = usbTransceiver
        cardOperationManager = CardOperationManager(usbTransceiver)
        return@withContext true
    }

    fun getCardOperationManager(): CardOperationManager {
        return cardOperationManager ?: throw IllegalStateException("USB card manager not initialized")
    }

    fun disconnect() {
        // Power off card slot
        try {
            transceiver?.iccPowerOff()
        } catch (e: Exception) {
            logger.debug("ICC Power Off error (non-fatal): ${e.message}")
        }

        transceiver?.disconnect()
        transceiver = null
        cardOperationManager = null

        // KHÔNG gọi usbDeviceManager.disconnect() ở đây!
        // Giữ USB connection alive để tránh kernel driver re-attach
        // trên composite device. Connection chỉ release khi plugin detach.
        usbDeviceManager.disconnect() // chỉ log, không release gì
    }

    @Throws(IOException::class)
    suspend fun executeWithUsbCard(block: suspend (CardOperationManager) -> Unit): Boolean {
        if (!connect()) {
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