package com.bmc.nfcsigner.core

object ApduCommandBuilder {

    fun createSelectAppletCommand(aid: ByteArray): ByteArray {
        return byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, aid.size.toByte()) + aid + byteArrayOf(0x00)
    }

    fun createVerifyPinCommand(pin: String): ByteArray {
        val pinBytes = pin.toByteArray(Charsets.UTF_8)
        return byteArrayOf(0x00, 0x20, 0x00, 0x81.toByte(), pinBytes.size.toByte()) + pinBytes
    }

    fun createComputeSignatureCommand(data: ByteArray, keyIndex: Int): ByteArray {
        val p1: Byte = 0x9E.toByte()
        val p2: Byte = when (keyIndex) {
            1 -> 0x9B.toByte()
            2 -> 0x9C.toByte()
            else -> 0x9A.toByte()
        }
        val lc = data.size.toByte()
        val le = 0x00.toByte()
        return byteArrayOf(0x00, 0x2A, p1, p2, lc) + data + byteArrayOf(le)
    }

    fun createGetRsaPublicKeyCommand(keyRole: String): ByteArray {
        val data = when (keyRole) {
            "sig" -> byteArrayOf(0xB6.toByte(), 0x00)
            "dec" -> byteArrayOf(0xB8.toByte(), 0x00)
            "aut" -> byteArrayOf(0xA4.toByte(), 0x00)
            "sm" -> byteArrayOf(0xA6.toByte(), 0x00)
            else -> throw IllegalArgumentException("Vai trò khóa không hợp lệ: $keyRole")
        }

        return byteArrayOf(0x00, 0x47, 0x81.toByte(), 0x00, data.size.toByte()) + data + byteArrayOf(0x00)
    }

    fun createSelectCertificateCommand(keyRole: String): ByteArray {
        val data = when (keyRole) {
            "sig", "dec", "aut", "sm" -> byteArrayOf(0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21)
            else -> throw IllegalArgumentException("Vai trò khóa không hợp lệ: $keyRole")
        }
        val lc = data.size.toByte()
        return byteArrayOf(0x00, 0xA5.toByte(), 0x02, 0x04, lc) + data + byteArrayOf(0x00)
    }

    fun createGetCertificateCommand(): ByteArray {
        return byteArrayOf(0x00, 0xCA.toByte(), 0x7F, 0x21, 0x00)
    }

    fun createGetResponseCommand(sw2: Int): ByteArray {
        return byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, sw2.toByte())
    }

    /**
     * Verify PIN for decryption operations (PW1 mode 82).
     * OpenPGP spec requires mode 0x82 for PSO:DECIPHER and INTERNAL AUTHENTICATE,
     * distinct from mode 0x81 used for PSO:CDS (signing).
     */
    fun createVerifyPinDecryptCommand(pin: String): ByteArray {
        val pinBytes = pin.toByteArray(Charsets.UTF_8)
        return byteArrayOf(0x00, 0x20, 0x00, 0x82.toByte(), pinBytes.size.toByte()) + pinBytes
    }

    /**
     * Build chained PSO:DECIPHER APDUs for RSA decryption.
     *
     * Prepends padding indicator byte 0x00 (PKCS#1 v1.5) to the ciphertext.
     * For RSA-4096: total = 1 + 512 = 513 bytes → 3 chained APDUs (255+255+3).
     *
     * CLA=0x10 for intermediate chunks, CLA=0x00 for the final chunk.
     * Le=0x00 appended only on the final chunk.
     *
     * @param encryptedData The RSA ciphertext (e.g. 512 bytes for RSA-4096)
     * @return List of APDU byte arrays to send in sequence
     */
    fun createDecipherCommands(encryptedData: ByteArray): List<ByteArray> {
        // Prepend padding indicator byte
        val fullData = byteArrayOf(0x00) + encryptedData
        val maxChunkSize = 255
        val chunks = fullData.toList().chunked(maxChunkSize)

        return chunks.mapIndexed { index, chunk ->
            val isLast = index == chunks.lastIndex
            val cla: Byte = if (isLast) 0x00 else 0x10
            val data = chunk.toByteArray()
            val apdu = byteArrayOf(cla, 0x2A, 0x80.toByte(), 0x86.toByte(), data.size.toByte()) + data
            if (isLast) apdu + byteArrayOf(0x00) else apdu  // Le=0x00 only on last
        }
    }
}