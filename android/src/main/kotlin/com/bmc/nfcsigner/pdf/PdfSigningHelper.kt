package com.bmc.nfcsigner.pdf

import android.content.Context
import com.bmc.nfcsigner.core.DebugLogger
import com.bmc.nfcsigner.core.CardOperationManager
import com.bmc.nfcsigner.models.SignatureConfig
import com.itextpdf.kernel.pdf.*
import com.itextpdf.kernel.utils.XmlProcessorCreator
import com.itextpdf.signatures.*
import com.itextpdf.kernel.geom.Rectangle
import com.itextpdf.io.image.ImageDataFactory
import com.itextpdf.kernel.font.PdfFontFactory
import com.itextpdf.io.font.PdfEncodings
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*

class PdfSigningHelper(private val context: Context) {

    private val logger = DebugLogger("PdfSignerHelper")

    init {
        // Ensure Bouncy Castle Provider is registered
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }

        // Fix iText 7.2.5 trên Android: thay thế DefaultSafeXmlParserFactory
        // vì Android's XML parser không hỗ trợ setXIncludeAware()
        XmlProcessorCreator.setXmlParserFactory(AndroidXmlParserFactory())
    }

    fun signPdf(
        pdfBytes: ByteArray,
        cardOperationManager: CardOperationManager,
        appletID: String,
        pin: String,
        keyIndex: Int,
        reason: String,
        location: String,
        pdfHashBytes: ByteArray,
        signatureConfig: SignatureConfig
    ): ByteArray {
        logger.debug("Starting PDF signing process (${pdfBytes.size} bytes)")

        // Select applet and verify PIN
        if (!cardOperationManager.selectApplet(hexStringToByteArray(appletID))) {
            throw IllegalStateException("Cannot select applet")
        }

        val (pinVerified, triesLeft) = cardOperationManager.verifyPin(pin)
        if (!pinVerified) {
            throw SecurityException("PIN verification failed. Tries left: $triesLeft")
        }

        // Get certificate
        logger.debug("Getting certificate from card...")
        val certificateBytes = cardOperationManager.getCertificate("sig")
        if (certificateBytes.isEmpty()) {
            throw IllegalStateException("Empty certificate received from card")
        }
        logger.debug("Certificate received: ${certificateBytes.size} bytes")

        val certificate = parseCertificate(certificateBytes)
        val certificateChain = arrayOf(certificate)
        logger.debug("Certificate parsed: ${certificate.subjectDN}")

        // Prepare PDF signing — use try-finally to ensure reader is closed
        val reader = PdfReader(ByteArrayInputStream(pdfBytes))
        try {
            val signedPdfStream = ByteArrayOutputStream()
            val stampingProperties = StampingProperties()
            val signer = PdfSigner(reader, signedPdfStream, stampingProperties)

            // Configure signature appearance
            logger.debug("Configuring signature appearance...")
            configureSignatureAppearance(signer, signatureConfig, reason, location)

            // Create external signature
            val externalSignature = createExternalSignature(cardOperationManager, pdfHashBytes, keyIndex)

            // Perform signing
            logger.debug("Calling signDetached...")
            signer.signDetached(
                BouncyCastleDigest(),
                externalSignature,
                certificateChain,
                null, null, null, 0,
                PdfSigner.CryptoStandard.CMS
            )

            logger.debug("PDF signing completed successfully (${signedPdfStream.size()} bytes)")
            return signedPdfStream.toByteArray()
        } catch (e: Exception) {
            logger.debug("PDF signing failed: ${e.message}")
            logger.debug("Stack trace: ${e.stackTraceToString()}")
            throw e
        } finally {
            try {
                reader.close()
            } catch (e: Exception) {
                logger.debug("Error closing PdfReader (non-fatal): ${e.message}")
            }
        }
    }

    private fun configureSignatureAppearance(
        signer: PdfSigner,
        config: SignatureConfig,
        reason: String,
        location: String
    ) {
        val pageRect = Rectangle(config.x, config.y, config.width, config.height)
        val appearance = signer.signatureAppearance

        appearance
            .setReason(reason)
            .setLocation(location)
            .setPageRect(pageRect)
            .setPageNumber(config.pageNumber)
            .setReuseAppearance(false)

        config.contact?.let { appearance.setContact(it) }

        // Configure visual appearance
        configureVisualAppearance(signer, appearance, config, location)
    }

    private fun configureVisualAppearance(
        signer: com.itextpdf.signatures.PdfSigner,
        appearance: PdfSignatureAppearance,
        config: SignatureConfig,
        location:String
    ) {
        val n2 = appearance.layer2
        val canvas = com.itextpdf.kernel.pdf.canvas.PdfCanvas(n2, signer.document)

        // Load fonts
        val fontRegular = loadFont("fonts/Helvetica.ttf")
        val fontBold = loadFont("fonts/Helvetica-Bold.ttf")

        val rect = appearance.pageRect
        val padding = 5f
        var textX = padding
        var textBlockWidth = rect.width - padding * 2

        // Add signature image if available (draw on same layer as text for 2-column layout)
        config.signatureImage?.let { imageBytes ->
            try {
                val imageData = ImageDataFactory.create(imageBytes)
                appearance.signatureGraphic = imageData
                appearance.renderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION

                // Draw image on layer2 (same as text) — left column
                val imgWidth = config.signatureImageWidth
                val imgHeight = config.signatureImageHeight
                val imgX = padding
                val imgY = (rect.height - imgHeight) / 2f

                canvas.addImageWithTransformationMatrix(imageData, imgWidth, 0f, 0f, imgHeight, imgX, imgY)

                // Text starts in right column
                textX = imgWidth + padding * 2
                textBlockWidth = rect.width - textX - padding
            } catch (e: Exception) {
                logger.debug("Failed to set signature image: ${e.message}")
                appearance.renderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION
            }
        } ?: run {
            appearance.renderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION
        }

        // Draw text information
        drawSignatureText(canvas, config, location, fontRegular, fontBold, rect, textX, textBlockWidth)
        canvas.release()
    }

    private fun drawSignatureText(
        canvas: com.itextpdf.kernel.pdf.canvas.PdfCanvas,
        config: SignatureConfig,
        location: String,
        fontRegular: com.itextpdf.kernel.font.PdfFont,
        fontBold: com.itextpdf.kernel.font.PdfFont,
        rect: Rectangle,
        startX: Float,
        maxWidth: Float
    ) {
        val lineHeight = 12f
        var currentY = rect.height - lineHeight

        // Signer name (bold)
        config.signerName?.let { name ->
            canvas.beginText()
                .setFontAndSize(fontBold, 9f)
                .moveText(startX.toDouble(), currentY.toDouble())
                .showText(name)
                .endText()
            currentY -= lineHeight
        }

        // Sign date
        config.signDate?.let { dateStr ->
            val formattedDate = formatDate(dateStr)
            canvas.beginText()
                .setFontAndSize(fontRegular, 7f)
                .moveText(startX.toDouble(), currentY.toDouble())
                .showText("Ngày: $formattedDate")
                .endText()
            currentY -= lineHeight
        }

        // Contact/Email
        config.contact?.let { contact ->
            canvas.beginText()
                .setFontAndSize(fontRegular, 7f)
                .moveText(startX.toDouble(), currentY.toDouble())
                .showText("Email: $contact")
                .endText()
            currentY -= lineHeight
        }

        // Location
        canvas.beginText()
            .setFontAndSize(fontRegular, 7f)
            .moveText(startX.toDouble(), currentY.toDouble())
            .showText("Location: ${location ?: "N/A"}")
            .endText()
    }

    private fun createExternalSignature(
        cardOperationManager: CardOperationManager,
        pdfHashBytes: ByteArray,
        keyIndex: Int
    ): IExternalSignature {
        return object : IExternalSignature {
            override fun getHashAlgorithm(): String = "SHA-256"
            override fun getEncryptionAlgorithm(): String = "RSA"

            override fun sign(message: ByteArray): ByteArray {
                logger.debug("Signing data, length: ${pdfHashBytes.size}")
                return cardOperationManager.generateSignature(pdfHashBytes, keyIndex)
            }
        }
    }

    private fun parseCertificate(certificateBytes: ByteArray): X509Certificate {
        return try {
            val certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider())
            certificateFactory.generateCertificate(ByteArrayInputStream(certificateBytes)) as X509Certificate
        } catch (e: Exception) {
            logger.debug("Bouncy Castle provider failed, trying system provider: ${e.message}")
            val certificateFactory = CertificateFactory.getInstance("X.509")
            certificateFactory.generateCertificate(ByteArrayInputStream(certificateBytes)) as X509Certificate
        }
    }

    private fun loadFont(path: String): com.itextpdf.kernel.font.PdfFont {
        val fontBytes = context.assets.open(path).use { it.readBytes() }
        return PdfFontFactory.createFont(
            fontBytes,
            PdfEncodings.IDENTITY_H,
            PdfFontFactory.EmbeddingStrategy.PREFER_EMBEDDED
        )
    }

    private fun formatDate(dateString: String): String {
        return try {
            val isoParser = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS", Locale.getDefault())
            val displayFormatter = SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.getDefault())
            val dateObject = isoParser.parse(dateString)
            displayFormatter.format(dateObject)
        } catch (e: Exception) {
            logger.debug("Date parsing error: ${e.message}")
            dateString
        }
    }

    private fun hexStringToByteArray(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Must have an even length" }
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}