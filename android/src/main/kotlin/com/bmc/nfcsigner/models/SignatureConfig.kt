package com.bmc.nfcsigner.models

data class SignatureConfig(
    val x: Float = 36f,
    val y: Float = 700f,
    val width: Float = 200f,
    val height: Float = 50f,
    val signatureImageWidth: Float = 50f,
    val signatureImageHeight: Float = 50f,
    val pageNumber: Int = 1,
    val signatureImage: ByteArray? = null,
    val contact: String? = null,
    val signerName: String? = null,
    val signDate: String? = null
) {
    companion object {
        fun fromMap(map: Map<String, Any>?): SignatureConfig {
            return SignatureConfig(
                x = (map?.get("x") as? Double)?.toFloat() ?: 36f,
                y = (map?.get("y") as? Double)?.toFloat() ?: 700f,
                width = (map?.get("width") as? Double)?.toFloat() ?: 200f,
                height = (map?.get("height") as? Double)?.toFloat() ?: 50f,
                signatureImageWidth = (map?.get("signatureImageWidth") as? Double)?.toFloat() ?: 50f,
                signatureImageHeight = (map?.get("signatureImageHeight") as? Double)?.toFloat() ?: 50f,
                pageNumber = map?.get("pageNumber") as? Int ?: 1,
                signatureImage = map?.get("signatureImage") as? ByteArray,
                contact = map?.get("contact") as? String,
                signerName = map?.get("signerName") as? String,
                signDate = map?.get("signDate") as? String
            )
        }
    }
}