package com.bmc.nfcsigner.pdf

import com.bmc.nfcsigner.core.DebugLogger
import com.itextpdf.kernel.utils.DefaultSafeXmlParserFactory
import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Custom XML parser factory cho Android.
 *
 * iText 7.2.5's DefaultSafeXmlParserFactory gọi setXIncludeAware(true)
 * nhưng Android's XML parser không hỗ trợ method này → throws UnsupportedOperationException.
 *
 * Kế thừa DefaultSafeXmlParserFactory và override createDocumentBuilderInstance
 * để tránh gọi setXIncludeAware().
 */
class AndroidXmlParserFactory : DefaultSafeXmlParserFactory() {

    private val logger = DebugLogger("AndroidXmlParserFactory")

    override fun createDocumentBuilderInstance(
        namespaceAware: Boolean,
        ignoringComments: Boolean
    ): DocumentBuilder {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = namespaceAware
        factory.isIgnoringComments = ignoringComments

        // Security: disable external entities (tránh XXE attacks)
        // KHÔNG gọi setXIncludeAware — Android không hỗ trợ
        try {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        } catch (e: Exception) {
            logger.debug("Some XML security features not supported (non-fatal): ${e.message}")
        }
        factory.isExpandEntityReferences = false

        return factory.newDocumentBuilder()
    }
}
