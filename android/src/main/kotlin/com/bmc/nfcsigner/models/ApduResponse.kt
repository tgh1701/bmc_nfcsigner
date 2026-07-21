package com.bmc.nfcsigner.models

data class ApduResponse(
    val data: ByteArray,
    val sw1: Int,
    val sw2: Int
) {
    val isSuccess: Boolean
        get() = sw1 == 0x90 && sw2 == 0x00

    val statusDetails: Map<String, Int>
        get() = mapOf("sw1" to sw1, "sw2" to sw2)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ApduResponse

        if (!data.contentEquals(other.data)) return false
        if (sw1 != other.sw1) return false
        if (sw2 != other.sw2) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + sw1
        result = 31 * result + sw2
        return result
    }
}