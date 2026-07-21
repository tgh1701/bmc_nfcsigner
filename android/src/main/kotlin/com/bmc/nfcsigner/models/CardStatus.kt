package com.bmc.nfcsigner.models

sealed class CardStatus {
    object Connected : CardStatus()
    object Disconnected : CardStatus()
    object Processing : CardStatus()
    data class Error(val message: String, val code: String) : CardStatus()
}