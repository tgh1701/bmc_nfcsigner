package com.bmc.nfcsigner.usb

import android.hardware.usb.*
import com.bmc.nfcsigner.core.DebugLogger
import com.bmc.nfcsigner.core.Transceiver
import com.bmc.nfcsigner.core.ResponseHandler
import com.bmc.nfcsigner.models.ApduResponse
import java.io.IOException

class UsbTransceiver(
    private val usbManager: UsbManager,
    private val usbDevice: UsbDevice,
    private val usbConnection: UsbDeviceConnection,
    private val usbInterface: UsbInterface,
    private val endpointIn: UsbEndpoint,
    private val endpointOut: UsbEndpoint,
    private val dwMaxCCIDMessageLength: Int = 65544
) : Transceiver {

    private val logger = DebugLogger("UsbTransceiver")
    private var sequenceNumber: Int = 0

    companion object {
        // CCID Message Types - PC to Reader
        private const val PC_TO_RDR_ICC_POWER_ON: Byte = 0x62
        private const val PC_TO_RDR_ICC_POWER_OFF: Byte = 0x63
        private const val PC_TO_RDR_XFR_BLOCK: Byte = 0x6F

        // CCID Message Types - Reader to PC
        private const val RDR_TO_PC_DATA_BLOCK: Int = 0x80
        private const val RDR_TO_PC_SLOT_STATUS: Int = 0x81

        // ICC Status values (bStatus bits 1:0)
        private const val ICC_STATUS_ACTIVE: Int = 0x00
        private const val ICC_STATUS_INACTIVE: Int = 0x01
        private const val ICC_STATUS_NOT_PRESENT: Int = 0x02

        // Response buffer size
        private const val RESPONSE_BUFFER_SIZE: Int = 4096

        // Timeout values
        private const val SEND_TIMEOUT_MS: Int = 5000
        private const val RECEIVE_TIMEOUT_MS: Int = 15000

        // Short timeout for pipe draining
        private const val DRAIN_TIMEOUT_MS: Int = 100

        // Maximum number of CCID time extension requests before giving up
        private const val MAX_TIME_EXTENSIONS: Int = 30

        // Small delay between consecutive APDU commands (ms)
        // Helps composite devices stabilize USB pipe state
        private const val INTER_COMMAND_DELAY_MS: Long = 10
    }

    override fun connect() {
        // USB connection is established in constructor
    }

    override fun disconnect() {
        // QUAN TRỌNG: KHÔNG gọi releaseInterface() / close() ở đây!
        // UsbDeviceManager.disconnect() sẽ quản lý lifecycle của USB connection.
        // Double releaseInterface() trên composite device sẽ corrupt USB state.
        logger.debug("UsbTransceiver disconnected")
    }

    override fun isConnected(): Boolean = usbConnection != null

    /**
     * Drain (đọc hết) dữ liệu cũ còn sót trong USB IN pipe.
     * Gọi trước khi bắt đầu session mới để tránh đọc phải data cũ.
     */
    private fun drainPipe() {
        val drainBuffer = ByteArray(RESPONSE_BUFFER_SIZE)
        var drained: Int
        var totalDrained = 0
        do {
            drained = usbConnection.bulkTransfer(endpointIn, drainBuffer, drainBuffer.size, DRAIN_TIMEOUT_MS)
            if (drained > 0) {
                totalDrained += drained
                logger.debug("Drained $drained bytes of stale data from USB IN pipe")
            }
        } while (drained > 0)

        if (totalDrained > 0) {
            logger.debug("Total drained: $totalDrained bytes")
        }
    }

    /**
     * Reset USB pipe state: drain stale data + reset sequence number.
     * Gọi trước mỗi session USB mới.
     */
    fun resetPipeState() {
        logger.debug("Resetting USB pipe state...")
        drainPipe()
        sequenceNumber = 0
        logger.debug("USB pipe state reset complete")
    }

    /**
     * Gửi PC_to_RDR_IccPowerOn (0x62) để kích hoạt card slot.
     * Trả về ATR (Answer To Reset) từ card.
     * Bước này BẮT BUỘC trước khi gửi APDU command, đặc biệt với composite device.
     */
    @Throws(IOException::class)
    fun iccPowerOn(): ByteArray {
        // Reset pipe state trước khi Power On — critical cho composite device
        resetPipeState()

        logger.debug("Sending ICC Power On...")

        val message = ByteArray(10)
        message[0] = PC_TO_RDR_ICC_POWER_ON  // Message Type
        // Bytes 1-4: Data length = 0 (no data payload for power on)
        message[1] = 0x00
        message[2] = 0x00
        message[3] = 0x00
        message[4] = 0x00
        message[5] = 0x00  // Slot number
        message[6] = nextSequenceNumber().toByte()  // Sequence number
        message[7] = 0x00  // PowerSelect: auto voltage selection
        message[8] = 0x00  // RFU
        message[9] = 0x00  // RFU

        logger.debug("ICC Power On → ${message.toHexString()}")

        // Send power on command
        val sent = usbConnection.bulkTransfer(endpointOut, message, message.size, SEND_TIMEOUT_MS)
        if (sent != message.size) {
            throw IOException("Failed to send ICC Power On: sent $sent of ${message.size} bytes")
        }

        // Receive response (RDR_to_PC_DataBlock with ATR)
        val ccidResponse = readCcidResponse()

        logger.debug("ICC Power On ← ${ccidResponse.toHexString()}")

        if (ccidResponse.size < 10) {
            throw IOException("ICC Power On response too short: ${ccidResponse.size} bytes")
        }

        val messageType = ccidResponse[0].toInt() and 0xFF
        if (messageType != RDR_TO_PC_DATA_BLOCK) {
            throw IOException("Unexpected response type for ICC Power On: 0x${messageType.toString(16)}")
        }

        // Check ICC status
        checkCcidStatus(ccidResponse)

        // Extract ATR data
        val dataLength = extractDataLength(ccidResponse)
        val atr = if (dataLength > 0 && 10 + dataLength <= ccidResponse.size) {
            ccidResponse.copyOfRange(10, 10 + dataLength)
        } else {
            byteArrayOf()
        }

        logger.debug("ICC Power On success, ATR: ${atr.toHexString()}")
        return atr
    }

    /**
     * Gửi PC_to_RDR_IccPowerOff (0x63) để tắt card slot.
     */
    @Throws(IOException::class)
    fun iccPowerOff() {
        logger.debug("Sending ICC Power Off...")

        val message = ByteArray(10)
        message[0] = PC_TO_RDR_ICC_POWER_OFF  // Message Type
        message[5] = 0x00  // Slot number
        message[6] = nextSequenceNumber().toByte()

        val sent = usbConnection.bulkTransfer(endpointOut, message, message.size, SEND_TIMEOUT_MS)
        if (sent != message.size) {
            logger.debug("Failed to send ICC Power Off")
        }

        // Read response but don't fail if it fails
        try {
            val responseBuffer = ByteArray(RESPONSE_BUFFER_SIZE)
            usbConnection.bulkTransfer(endpointIn, responseBuffer, responseBuffer.size, RECEIVE_TIMEOUT_MS)
        } catch (e: Exception) {
            logger.debug("Error reading ICC Power Off response: ${e.message}")
        }

        // Drain any remaining data after power off
        drainPipe()

        logger.debug("ICC Power Off sent")
    }

    @Throws(IOException::class)
    override fun transceive(command: ByteArray): ApduResponse {
        logger.debug("USB → ${command.toHexString()} (${command.size} bytes)")

        val ccidMessage = createCcidMessage(command)

        // Send command
        val sent = usbConnection.bulkTransfer(endpointOut, ccidMessage, ccidMessage.size, SEND_TIMEOUT_MS)
        if (sent != ccidMessage.size) {
            throw IOException("Failed to send CCID message: sent $sent of ${ccidMessage.size} bytes")
        }

        // Receive response — with time extension, CCID chaining, and composite device handling
        val ccidResponse = readFullCcidResponse()

        logger.debug("USB ← (${ccidResponse.size} bytes) ${ccidResponse.toHexString()}")

        return parseCcidResponse(ccidResponse)
    }

    /**
     * Đọc CCID response đầy đủ bao gồm:
     * 1. CCID Time Extension handling (card cần thêm thời gian)
     * 2. CCID-level response chaining (response vượt quá dwMaxCCIDMessageLength)
     *
     * CCID-level chaining (khác với APDU-level GET RESPONSE):
     * - Reader chia response lớn thành nhiều RDR_to_PC_DataBlock
     * - bChainParameter (byte 9) = 0x01/0x03: còn data tiếp theo
     * - Host gửi empty PC_to_RDR_XfrBlock với wLevelParameter=0x0010 để yêu cầu block tiếp
     * - Đặc biệt quan trọng trên composite device với dwMaxCCIDMessageLength nhỏ
     */
    @Throws(IOException::class)
    private fun readFullCcidResponse(): ByteArray {
        var timeExtensionCount = 0

        // Read first CCID block (with time extension handling)
        var ccidResponse = readFirstCcidBlock({ timeExtensionCount++ }, timeExtensionCount)

        if (ccidResponse.size < 10) {
            return ccidResponse
        }

        // Check bChainParameter (byte 9) for CCID-level response chaining
        var chainParam = ccidResponse[9].toInt() and 0xFF

        if (chainParam == 0x01 || chainParam == 0x03) {
            // CCID-level chaining detected — collect all data blocks
            logger.debug("CCID response chaining detected (bChainParameter=0x${chainParam.toString(16)})")
            logger.debug("  dwMaxCCIDMessageLength=$dwMaxCCIDMessageLength, first block: ${ccidResponse.size} bytes")

            // Extract APDU data from the first block
            val firstDataLength = extractDataLength(ccidResponse)
            val allData = mutableListOf<Byte>()
            if (firstDataLength > 0 && 10 + firstDataLength <= ccidResponse.size) {
                allData.addAll(ccidResponse.copyOfRange(10, 10 + firstDataLength).toList())
            }

            var blockCount = 1

            // Request continuation blocks until complete
            while (chainParam == 0x01 || chainParam == 0x03) {
                blockCount++

                // Send empty XfrBlock requesting next data block
                val continueMsg = createCcidContinueRequest()
                val sent = usbConnection.bulkTransfer(endpointOut, continueMsg, continueMsg.size, SEND_TIMEOUT_MS)
                if (sent != continueMsg.size) {
                    throw IOException("Failed to send CCID continue request: sent $sent of ${continueMsg.size}")
                }

                // Read next block (with time extension handling)
                val nextBlock = readFirstCcidBlock({ timeExtensionCount++ }, timeExtensionCount)

                if (nextBlock.size < 10) {
                    logger.debug("CCID chain block $blockCount: too short (${nextBlock.size} bytes), stopping")
                    break
                }

                // Verify it's a DataBlock
                val msgType = nextBlock[0].toInt() and 0xFF
                if (msgType != RDR_TO_PC_DATA_BLOCK) {
                    logger.debug("CCID chain block $blockCount: unexpected type 0x${msgType.toString(16)}")
                    break
                }

                // Extract data from this block
                val blockDataLen = extractDataLength(nextBlock)
                if (blockDataLen > 0 && 10 + blockDataLen <= nextBlock.size) {
                    allData.addAll(nextBlock.copyOfRange(10, 10 + blockDataLen).toList())
                }

                chainParam = nextBlock[9].toInt() and 0xFF
                logger.debug("CCID chain block $blockCount: ${blockDataLen} bytes, chainParam=0x${chainParam.toString(16)}, total=${allData.size}")
            }

            logger.debug("CCID chaining complete: $blockCount blocks, ${allData.size} total APDU bytes")

            // Reconstruct a single CCID message with all data
            val totalData = allData.toByteArray()
            val assembled = ByteArray(10 + totalData.size)
            // Copy header from first block
            System.arraycopy(ccidResponse, 0, assembled, 0, 10)
            // Update data length in header
            assembled[1] = (totalData.size and 0xFF).toByte()
            assembled[2] = ((totalData.size shr 8) and 0xFF).toByte()
            assembled[3] = ((totalData.size shr 16) and 0xFF).toByte()
            assembled[4] = ((totalData.size shr 24) and 0xFF).toByte()
            // Clear chain parameter
            assembled[9] = 0x00
            // Copy assembled data
            System.arraycopy(totalData, 0, assembled, 10, totalData.size)

            return assembled
        }

        return ccidResponse
    }

    /**
     * Đọc một CCID block với xử lý Time Extension.
     */
    @Throws(IOException::class)
    private fun readFirstCcidBlock(onTimeExtension: () -> Unit, currentExtCount: Int): ByteArray {
        var extensionCount = currentExtCount

        while (true) {
            val ccidResponse = readCcidResponse()

            if (ccidResponse.size < 10) {
                return ccidResponse
            }

            val bStatus = ccidResponse[7].toInt() and 0xFF
            val commandStatus = (bStatus shr 6) and 0x03

            // commandStatus == 2 → Time Extension request
            if (commandStatus == 2) {
                extensionCount++
                onTimeExtension()
                logger.debug("CCID Time Extension #$extensionCount — card needs more time")

                if (extensionCount > MAX_TIME_EXTENSIONS) {
                    throw IOException("Card exceeded maximum time extensions ($MAX_TIME_EXTENSIONS)")
                }
                continue
            }

            if (extensionCount > currentExtCount) {
                logger.debug("Card responded after ${extensionCount - currentExtCount} time extension(s)")
            }

            return ccidResponse
        }
    }

    /**
     * Đọc CCID response từ USB IN pipe.
     * Đảm bảo đọc đủ data theo data length trong CCID header.
     *
     * QUAN TRỌNG cho composite device:
     * - Sử dụng buffer riêng + System.arraycopy thay vì offset-based bulkTransfer
     *   (5-param API có known issues trên một số Android chipsets/composite USB)
     * - Composite device thường chia CCID response thành nhiều USB packet
     *   (~250 bytes = max packet size của Bulk endpoint)
     */
    @Throws(IOException::class)
    private fun readCcidResponse(): ByteArray {
        val responseBuffer = ByteArray(RESPONSE_BUFFER_SIZE)
        val received = usbConnection.bulkTransfer(endpointIn, responseBuffer, responseBuffer.size, RECEIVE_TIMEOUT_MS)
        if (received <= 0) {
            throw IOException("No response received from USB device (received=$received)")
        }

        // Kiểm tra xem đã đọc đủ data chưa (theo CCID header)
        if (received >= 10) {
            val expectedDataLength = (responseBuffer[1].toInt() and 0xFF) or
                    ((responseBuffer[2].toInt() and 0xFF) shl 8) or
                    ((responseBuffer[3].toInt() and 0xFF) shl 16) or
                    ((responseBuffer[4].toInt() and 0xFF) shl 24)
            val expectedTotal = 10 + expectedDataLength

            if (received < expectedTotal) {
                // Chưa đủ data → đọc tiếp bằng buffer riêng + System.arraycopy
                // KHÔNG dùng offset-based bulkTransfer(5-param) — unreliable trên composite device
                logger.debug("Partial CCID response: got $received of $expectedTotal bytes, reading more...")
                val fullBuffer = ByteArray(maxOf(expectedTotal, RESPONSE_BUFFER_SIZE))
                System.arraycopy(responseBuffer, 0, fullBuffer, 0, received)
                var totalReceived = received

                while (totalReceived < expectedTotal) {
                    // Đọc vào buffer tạm riêng biệt — tránh issues với offset-based API
                    val tempBuffer = ByteArray(RESPONSE_BUFFER_SIZE)
                    val extra = usbConnection.bulkTransfer(
                        endpointIn,
                        tempBuffer,
                        tempBuffer.size,
                        RECEIVE_TIMEOUT_MS
                    )
                    if (extra <= 0) {
                        logger.debug("Failed to read remaining CCID data: got $totalReceived of $expectedTotal bytes (extra=$extra)")
                        break
                    }

                    // Copy vào fullBuffer, giới hạn không vượt quá expectedTotal
                    val copyLen = minOf(extra, expectedTotal - totalReceived)
                    System.arraycopy(tempBuffer, 0, fullBuffer, totalReceived, copyLen)
                    totalReceived += copyLen
                    logger.debug("Read $extra more bytes, total: $totalReceived / $expectedTotal")
                }

                return fullBuffer.copyOf(totalReceived)
            }
        }

        return responseBuffer.copyOf(received)
    }

    private fun createCcidMessage(apdu: ByteArray): ByteArray {
        val message = ByteArray(10 + apdu.size)
        message[0] = PC_TO_RDR_XFR_BLOCK  // Message Type: PC_to_RDR_XfrBlock

        // Data length (little-endian)
        val dataLength = apdu.size
        message[1] = (dataLength and 0xFF).toByte()
        message[2] = ((dataLength shr 8) and 0xFF).toByte()
        message[3] = ((dataLength shr 16) and 0xFF).toByte()
        message[4] = ((dataLength shr 24) and 0xFF).toByte()

        message[5] = 0x00  // Slot number
        message[6] = nextSequenceNumber().toByte()  // Sequence number (incrementing)
        message[7] = 0x00  // BWI (Block Waiting Timeout)
        message[8] = 0x00  // levelParameter (for APDU level: 0x0000)
        message[9] = 0x00  // levelParameter

        System.arraycopy(apdu, 0, message, 10, apdu.size)
        return message
    }

    /**
     * Tạo CCID continue request — empty PC_to_RDR_XfrBlock với wLevelParameter = 0x0010.
     * Dùng để yêu cầu reader gửi block tiếp theo trong CCID-level response chaining.
     */
    private fun createCcidContinueRequest(): ByteArray {
        val message = ByteArray(10)
        message[0] = PC_TO_RDR_XFR_BLOCK  // Message Type

        // Data length = 0 (empty XfrBlock)
        message[1] = 0x00
        message[2] = 0x00
        message[3] = 0x00
        message[4] = 0x00

        message[5] = 0x00  // Slot number
        message[6] = nextSequenceNumber().toByte()  // Sequence number
        message[7] = 0x00  // BWI
        message[8] = 0x10  // wLevelParameter = 0x0010 (request next data block)
        message[9] = 0x00  // wLevelParameter high byte

        return message
    }

    private fun parseCcidResponse(ccidResponse: ByteArray): ApduResponse {
        if (ccidResponse.size < 10) {
            throw IOException("CCID response too short: ${ccidResponse.size} bytes")
        }

        val messageType = ccidResponse[0].toInt() and 0xFF

        when (messageType) {
            RDR_TO_PC_DATA_BLOCK -> {
                // Normal data response — parse APDU
            }
            RDR_TO_PC_SLOT_STATUS -> {
                // SlotStatus (0x81) — composite device có thể trả về khi card state thay đổi
                // Chỉ chứa status, không có APDU data
                logger.debug("Received RDR_to_PC_SlotStatus instead of DataBlock")
                val bStatus = ccidResponse[7].toInt() and 0xFF
                val bError = ccidResponse[8].toInt() and 0xFF
                throw IOException("Card returned SlotStatus: bStatus=0x${bStatus.toString(16)}, bError=0x${bError.toString(16)}. Card may need power cycle.")
            }
            else -> {
                throw IOException("Unexpected CCID message type: 0x${messageType.toString(16)}")
            }
        }

        // Check ICC status and error
        checkCcidStatus(ccidResponse)

        val dataLength = extractDataLength(ccidResponse)

        return if (dataLength > 0 && 10 + dataLength <= ccidResponse.size) {
            val apduResponse = ccidResponse.copyOfRange(10, 10 + dataLength)
            ResponseHandler.parseResponse(apduResponse)
        } else {
            ApduResponse(byteArrayOf(), 0x90, 0x00)
        }
    }

    /**
     * Kiểm tra bStatus (byte 7) và bError (byte 8) trong CCID response.
     *
     * bStatus bits 1:0 (ICC Status):
     *   00 = ICC present and active
     *   01 = ICC present and inactive
     *   10 = No ICC present
     *
     * bStatus bit 6 (Command Status):
     *   0 = Processed without error
     *   1 = Failed
     */
    @Throws(IOException::class)
    private fun checkCcidStatus(ccidResponse: ByteArray) {
        val bStatus = ccidResponse[7].toInt() and 0xFF
        val bError = ccidResponse[8].toInt() and 0xFF
        val iccStatus = bStatus and 0x03
        val commandStatus = (bStatus shr 6) and 0x03

        logger.debug("CCID Status: bStatus=0x${bStatus.toString(16)}, bError=0x${bError.toString(16)}, iccStatus=$iccStatus, cmdStatus=$commandStatus")

        when (iccStatus) {
            ICC_STATUS_INACTIVE -> throw IOException("ICC present but inactive (not powered on). bError=0x${bError.toString(16)}")
            ICC_STATUS_NOT_PRESENT -> throw IOException("No ICC present in slot. bError=0x${bError.toString(16)}")
        }

        if (commandStatus != 0) {
            throw IOException("CCID command failed: bStatus=0x${bStatus.toString(16)}, bError=0x${bError.toString(16)}")
        }
    }

    /**
     * Extract data length (little-endian 4 bytes) từ CCID response.
     */
    private fun extractDataLength(ccidResponse: ByteArray): Int {
        return (ccidResponse[1].toInt() and 0xFF) or
                ((ccidResponse[2].toInt() and 0xFF) shl 8) or
                ((ccidResponse[3].toInt() and 0xFF) shl 16) or
                ((ccidResponse[4].toInt() and 0xFF) shl 24)
    }

    /**
     * Tạo sequence number tăng dần (0-255, wrap around).
     */
    private fun nextSequenceNumber(): Int {
        val seq = sequenceNumber
        sequenceNumber = (sequenceNumber + 1) and 0xFF
        return seq
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}