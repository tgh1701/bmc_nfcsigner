package com.bmc.nfcsigner.core

import com.bmc.nfcsigner.models.ApduResponse

object ResponseHandler {

    private val logger = DebugLogger("ResponseHandler")

    // Số lần retry tối đa khi GET RESPONSE trả về empty trên composite device
    private const val MAX_GET_RESPONSE_RETRIES = 2

    fun parseResponse(response: ByteArray): ApduResponse {
        return if (response.size >= 2) {
            val data = response.copyOfRange(0, response.size - 2)
            val sw1 = response[response.size - 2].toInt() and 0xFF
            val sw2 = response[response.size - 1].toInt() and 0xFF
            ApduResponse(data, sw1, sw2)
        } else {
            ApduResponse(byteArrayOf(), 0, 0)
        }
    }

    /**
     * Xử lý APDU GET RESPONSE chaining (SW1=0x61).
     *
     * @param initialResponse Response đầu tiên từ card
     * @param transceiver Hàm gửi APDU command
     * @param interCommandDelayMs Delay giữa các GET RESPONSE command (ms).
     *        Trên composite device, cần delay nhỏ (~10-50ms) để USB pipe ổn định.
     *        Trên NFC, nên để 0 (không delay).
     */
    fun handleGetResponse(
        initialResponse: ApduResponse,
        interCommandDelayMs: Long = 0,
        transceiver: (ByteArray) -> ApduResponse
    ): ApduResponse {
        var response = initialResponse
        var sw1 = response.sw1
        var sw2 = response.sw2

        if (sw1 != 0x61) {
            return response
        }

        val fullResponseData = response.data.toMutableList()
        var chunkIndex = 0

        while (sw1 == 0x61) {
            chunkIndex++

            // Delay giữa các GET RESPONSE — critical cho composite device
            if (interCommandDelayMs > 0) {
                Thread.sleep(interCommandDelayMs)
            }

            val getResponseCommand = ApduCommandBuilder.createGetResponseCommand(sw2)

            var retryCount = 0
            var gotValidResponse = false

            while (retryCount <= MAX_GET_RESPONSE_RETRIES && !gotValidResponse) {
                try {
                    response = transceiver(getResponseCommand)
                    sw1 = response.sw1
                    sw2 = response.sw2

                    // Kiểm tra response có hợp lệ không
                    if (response.data.isEmpty() && sw1 != 0x90 && sw1 != 0x61) {
                        // Response trống + SW lạ → có thể do composite device interference
                        retryCount++
                        if (retryCount <= MAX_GET_RESPONSE_RETRIES) {
                            logger.debug("GET RESPONSE chunk $chunkIndex returned empty (SW=${sw1.toString(16)}${sw2.toString(16)}), retry $retryCount/$MAX_GET_RESPONSE_RETRIES")
                            Thread.sleep(50L * retryCount) // Progressive delay
                            continue
                        }
                    }

                    gotValidResponse = true
                } catch (e: Exception) {
                    retryCount++
                    if (retryCount > MAX_GET_RESPONSE_RETRIES) {
                        throw e
                    }
                    logger.debug("GET RESPONSE chunk $chunkIndex failed: ${e.message}, retry $retryCount/$MAX_GET_RESPONSE_RETRIES")
                    Thread.sleep(50L * retryCount)
                }
            }

            logger.debug("GET RESPONSE chunk $chunkIndex: ${response.data.size} bytes, SW=${sw1.toString(16)}${sw2.toString(16)}")
            fullResponseData.addAll(response.data.toList())
        }

        logger.debug("GET RESPONSE complete: $chunkIndex chunks, ${fullResponseData.size} total bytes")
        return ApduResponse(fullResponseData.toByteArray(), sw1, sw2)
    }
}