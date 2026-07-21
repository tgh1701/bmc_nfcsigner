package com.bmc.nfcsigner.core

import com.bmc.nfcsigner.models.ApduResponse
import com.bmc.nfcsigner.usb.UsbTransceiver
import java.io.IOException

class CardOperationManager(private val transceiver: Transceiver) {

    private val logger = DebugLogger("CardOperationManager")

    /**
     * Delay giữa các GET RESPONSE command (ms).
     * Trên USB composite device, cần delay nhỏ để USB pipe ổn định.
     * Trên NFC, không cần delay.
     */
    private val interCommandDelayMs: Long = if (transceiver is UsbTransceiver) 15L else 0L

    @Throws(IOException::class)
    private fun executeCommandWithGetResponse(command: ByteArray): ApduResponse {
        val initialResponse = transceiver.transceive(command)
        return ResponseHandler.handleGetResponse(initialResponse, interCommandDelayMs = interCommandDelayMs) { getResponseCommand ->
            transceiver.transceive(getResponseCommand)
        }
    }

    fun selectApplet(aid: ByteArray): Boolean {
        logger.debug("Selecting applet: ${aid.toHexString()}")
        val command = ApduCommandBuilder.createSelectAppletCommand(aid)
        val response = transceiver.transceive(command)
        return response.isSuccess
    }

    fun verifyPin(pin: String): Pair<Boolean, Int> {
        logger.debug("Verifying PIN")
        val command = ApduCommandBuilder.createVerifyPinCommand(pin)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            val triesLeft = if (response.sw1 == 0x63 && response.sw2 >= 0xC0) {
                response.sw2 - 0xC0
            } else {
                0
            }
            return Pair(false, triesLeft)
        }

        return Pair(true, 0)
    }

    fun generateSignature(data: ByteArray, keyIndex: Int): ByteArray {
        logger.debug("Generating signature for ${data.size} bytes, keyIndex: $keyIndex")
        val command = ApduCommandBuilder.createComputeSignatureCommand(data, keyIndex)
        val response = executeCommandWithGetResponse(command)

        if (!response.isSuccess) {
            throw IOException("Signature generation failed: SW=${response.sw1.toString(16)}${response.sw2.toString(16)}")
        }

        return response.data
    }

    fun getRsaPublicKey(keyRole: String): ByteArray {
        logger.debug("Getting RSA public key for role: $keyRole")
        val command = ApduCommandBuilder.createGetRsaPublicKeyCommand(keyRole)
        val response = executeCommandWithGetResponse(command)

        if (!response.isSuccess) {
            throw IOException("Get public key failed: SW=${response.sw1.toString(16)}${response.sw2.toString(16)}")
        }

        return response.data
    }

    fun getCertificate(keyRole: String): ByteArray {
        logger.debug("Getting certificate for role: $keyRole")

        // Select certificate data first
        val selectCommand = ApduCommandBuilder.createSelectCertificateCommand(keyRole)
        val selectResponse = transceiver.transceive(selectCommand)

        if (!selectResponse.isSuccess) {
            throw IOException("Select certificate failed: SW=${selectResponse.sw1.toString(16)}${selectResponse.sw2.toString(16)}")
        }

        // Get certificate
        val getCertCommand = ApduCommandBuilder.createGetCertificateCommand()
        val certResponse = executeCommandWithGetResponse(getCertCommand)

        if (!certResponse.isSuccess) {
            throw IOException("Get certificate failed: SW=${certResponse.sw1.toString(16)}${certResponse.sw2.toString(16)}")
        }

        return certResponse.data
    }

    /**
     * Verify PIN for decryption operations (PW1 mode 82).
     * OpenPGP spec requires mode 0x82 for PSO:DECIPHER.
     */
    fun verifyPinForDecrypt(pin: String): Pair<Boolean, Int> {
        logger.debug("Verifying PIN for decrypt (mode 82)")
        val command = ApduCommandBuilder.createVerifyPinDecryptCommand(pin)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            val triesLeft = if (response.sw1 == 0x63 && response.sw2 >= 0xC0) {
                response.sw2 - 0xC0
            } else {
                0
            }
            return Pair(false, triesLeft)
        }

        return Pair(true, 0)
    }

    /**
     * Decrypt data using PSO:DECIPHER with command chaining.
     *
     * Sends chained APDUs for RSA decryption. Intermediate chunks (CLA=0x10)
     * are sent directly. The final chunk (CLA=0x00) is handled with GET RESPONSE
     * to collect the complete decrypted data.
     *
     * @param encryptedData The RSA ciphertext (e.g. 512 bytes for RSA-4096)
     * @return Decrypted plaintext bytes
     * @throws IOException if decryption fails
     */
    fun decryptData(encryptedData: ByteArray): ByteArray {
        logger.debug("Decrypting ${encryptedData.size} bytes (RSA ciphertext)")
        val commands = ApduCommandBuilder.createDecipherCommands(encryptedData)
        logger.debug("PSO:DECIPHER split into ${commands.size} chained APDUs")

        for ((index, command) in commands.withIndex()) {
            val isLast = (index == commands.lastIndex)

            if (isLast) {
                // Final chunk — handle GET RESPONSE for complete decrypted data
                val response = executeCommandWithGetResponse(command)
                if (!response.isSuccess) {
                    throw IOException("PSO:DECIPHER failed: SW=${response.sw1.toString(16)}${response.sw2.toString(16)}")
                }
                return response.data
            } else {
                // Intermediate chunk — just send and verify 9000
                if (interCommandDelayMs > 0) {
                    Thread.sleep(interCommandDelayMs)
                }
                val response = transceiver.transceive(command)
                if (!response.isSuccess) {
                    throw IOException("PSO:DECIPHER chaining failed at chunk ${index+1}: SW=${response.sw1.toString(16)}${response.sw2.toString(16)}")
                }
                logger.debug("PSO:DECIPHER chunk ${index+1}/${commands.size} OK")
            }
        }

        throw IOException("PSO:DECIPHER: no chunks to process")
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}
