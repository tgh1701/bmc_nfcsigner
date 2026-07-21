import 'dart:convert';
import 'dart:typed_data';
import '../models/service_result.dart';
import '../models/xml_signature_config.dart';
import 'crypto_utils.dart';

/// Lớp chuyên xử lý ký số XML theo chuẩn XML-DSig
class XmlSigner {
  /// Ký số một tài liệu XML theo chuẩn XML-DSig
  ///
  /// [xmlContent] là nội dung XML cần ký
  /// [signatureBytes] là chữ ký số (đã được tạo từ thẻ)
  /// [certificateBytes] là certificate (đã được lấy từ thẻ)
  /// [config] là cấu hình cho chữ ký XML
  /// Trả về XML đã được ký số
  static String signXml({
    required String xmlContent,
    required Uint8List signatureBytes,
    required Uint8List certificateBytes,
    required XmlSignatureConfig config,
  }) {
    try {
      // Parse XML gốc
      final xmlDoc = _parseXmlDocument(xmlContent);

      // Tạo cấu trúc chữ ký XML
      final signatureElement = _createSignatureElement(
        signatureBytes,
        certificateBytes,
        config,
      );

      // Chèn chữ ký vào tài liệu XML
      _embedSignature(xmlDoc, signatureElement, config);

      // Serialize XML đã ký thành chuỗi
      return _serializeXmlDocument(xmlDoc);
    } catch (e) {
      throw Exception('Lỗi ký XML: $e');
    }
  }

  /// Tạo DigestInfo cho dữ liệu cần ký (theo chuẩn PKCS#1)
  static Uint8List createDigestInfoForXml({
    required String xmlContent,
    required XmlSignatureConfig config,
  }) {
    try {
      // Chuẩn hóa XML theo canonicalization method
      final canonicalXml = _canonicalizeXml(xmlContent, config);

      // Tính hash của XML đã chuẩn hóa
      final hash = CryptoUtils.sha256Hash(utf8.encode(canonicalXml));

      // Tạo DigestInfo structure theo PKCS#1
      return CryptoUtils.createSha256DigestInfo(hash);
    } catch (e) {
      throw Exception('Lỗi tạo DigestInfo: $e');
    }
  }

  // ========== PRIVATE METHODS ==========

  /// Parse XML document từ chuỗi
  static dynamic _parseXmlDocument(String xmlContent) {
    // Sử dụng XML parser đơn giản
    // Trong thực tế, bạn có thể sử dụng package xml hoặc triển khai parser đơn giản
    return {'content': xmlContent, 'signatures': []};
  }

  /// Tạo phần tử Signature theo chuẩn XML-DSig
  static String _createSignatureElement(
      Uint8List signatureBytes,
      Uint8List certificateBytes,
      XmlSignatureConfig config,
      ) {
    final signatureId = config.signatureId ?? 'signature-${DateTime.now().millisecondsSinceEpoch}';
    final signatureB64 = base64.encode(signatureBytes);
    final certificateB64 = base64.encode(certificateBytes);

    final buffer = StringBuffer();

    // Bắt đầu phần tử Signature
    buffer.write('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"');
    if (signatureId.isNotEmpty) {
      buffer.write(' Id="$signatureId"');
    }
    buffer.write('>');

    // SignedInfo
    buffer.write('<ds:SignedInfo>');

    // CanonicalizationMethod
    buffer.write('<ds:CanonicalizationMethod Algorithm="${config.canonicalizationMethod}"/>');

    // SignatureMethod
    buffer.write('<ds:SignatureMethod Algorithm="${config.signatureMethod}"/>');

    // Reference
    buffer.write('<ds:Reference');
    if (config.referenceUri != null) {
      buffer.write(' URI="${config.referenceUri}"');
    }
    buffer.write('>');

    // Transforms
    buffer.write('<ds:Transforms>');
    if (config.enveloped) {
      buffer.write('<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>');
    }
    buffer.write('<ds:Transform Algorithm="${config.canonicalizationMethod}"/>');
    buffer.write('</ds:Transforms>');

    // DigestMethod
    buffer.write('<ds:DigestMethod Algorithm="${config.digestMethod}"/>');

    // DigestValue (sẽ được tính toán sau)
    buffer.write('<ds:DigestValue>${_calculateXmlDigest("", config)}</ds:DigestValue>');

    buffer.write('</ds:Reference>');
    buffer.write('</ds:SignedInfo>');

    // SignatureValue
    buffer.write('<ds:SignatureValue>$signatureB64</ds:SignatureValue>');

    // KeyInfo (nếu có certificate)
    if (config.includeCertificate) {
      buffer.write('<ds:KeyInfo>');
      buffer.write('<ds:X509Data>');
      buffer.write('<ds:X509Certificate>$certificateB64</ds:X509Certificate>');
      buffer.write('</ds:X509Data>');
      buffer.write('</ds:KeyInfo>');
    }

    buffer.write('</ds:Signature>');

    return buffer.toString();
  }

  /// Tính toán digest cho XML
  static String _calculateXmlDigest(String xmlContent, XmlSignatureConfig config) {
    final canonicalXml = _canonicalizeXml(xmlContent, config);
    final hash = CryptoUtils.sha256Hash(utf8.encode(canonicalXml));
    return base64.encode(hash);
  }

  /// Chuẩn hóa XML theo canonicalization method
  static String _canonicalizeXml(String xmlContent, XmlSignatureConfig config) {
    // Triển khai đơn giản - trong thực tế cần triển khai canonicalization phức tạp hơn
    switch (config.canonicalizationMethod) {
      case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
        return _canonicalizeXmlC14n(xmlContent);
      case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
        return _canonicalizeXmlC14nWithComments(xmlContent);
      default:
        return xmlContent;
    }
  }

  /// Canonicalization C14N đơn giản
  static String _canonicalizeXmlC14n(String xmlContent) {
    // Loại bỏ khoảng trắng thừa, chuẩn hóa line endings, v.v.
    return xmlContent
        .replaceAll(RegExp(r'>\s+<'), '><') // Loại bỏ khoảng trắng giữa các thẻ
        .replaceAll(RegExp(r'\s+'), ' ') // Chuẩn hóa khoảng trắng
        .trim();
  }

  /// Canonicalization C14N với comments
  static String _canonicalizeXmlC14nWithComments(String xmlContent) {
    // Giữ nguyên comments
    return xmlContent
        .replaceAll(RegExp(r'>\s+<'), '><')
        .replaceAll(RegExp(r'\s+'), ' ')
        .trim();
  }

  /// Chèn chữ ký vào tài liệu XML
  static void _embedSignature(
      dynamic xmlDoc,
      String signatureElement,
      XmlSignatureConfig config,
      ) {
    // Logic chèn chữ ký vào vị trí thích hợp trong XML
    // Tùy thuộc vào cấu hình enveloped, xpath, v.v.
    if (config.enveloped) {
      _embedAsEnvelopedSignature(xmlDoc, signatureElement);
    }
  }

  /// Chèn chữ ký dạng enveloped
  static void _embedAsEnvelopedSignature(dynamic xmlDoc, String signatureElement) {
    // Chèn chữ ký vào cuối phần tử gốc
    // Đây là triển khai đơn giản - trong thực tế cần xử lý phức tạp hơn
    if (xmlDoc is Map) {
      final content = xmlDoc['content'] as String;
      // Tìm vị trí đóng thẻ gốc và chèn chữ ký trước đó
      final lastCloseTag = content.lastIndexOf('</');
      if (lastCloseTag != -1) {
        final newContent = content.substring(0, lastCloseTag) +
            signatureElement +
            content.substring(lastCloseTag);
        xmlDoc['content'] = newContent;
      }
    }
  }

  /// Serialize XML document thành chuỗi
  static String _serializeXmlDocument(dynamic xmlDoc) {
    if (xmlDoc is Map) {
      return xmlDoc['content'] as String;
    }
    return xmlDoc.toString();
  }
}