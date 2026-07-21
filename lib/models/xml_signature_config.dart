/// Cấu hình ký XML theo chuẩn XML-DSig
class XmlSignatureConfig {
  final String? signatureId;
  final String canonicalizationMethod;
  final String signatureMethod;
  final String digestMethod;
  final String? referenceUri;
  final Map<String, String>? namespaces;
  final bool includeCertificate;
  final bool enveloped;
  final String? xpath;

  const XmlSignatureConfig({
    this.signatureId,
    this.canonicalizationMethod = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    this.signatureMethod = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    this.digestMethod = 'http://www.w3.org/2001/04/xmlenc#sha256',
    this.referenceUri,
    this.namespaces,
    this.includeCertificate = true,
    this.enveloped = true,
    this.xpath,
  });

  Map<String, dynamic> toMap() {
    return {
      'signatureId': signatureId,
      'canonicalizationMethod': canonicalizationMethod,
      'signatureMethod': signatureMethod,
      'digestMethod': digestMethod,
      'referenceUri': referenceUri,
      'namespaces': namespaces,
      'includeCertificate': includeCertificate,
      'enveloped': enveloped,
      'xpath': xpath,
    };
  }

  static XmlSignatureConfig fromMap(Map<String, dynamic> map) {
    return XmlSignatureConfig(
      signatureId: map['signatureId'],
      canonicalizationMethod: map['canonicalizationMethod'] ?? 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
      signatureMethod: map['signatureMethod'] ?? 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      digestMethod: map['digestMethod'] ?? 'http://www.w3.org/2001/04/xmlenc#sha256',
      referenceUri: map['referenceUri'],
      namespaces: map['namespaces'] != null ? Map<String, String>.from(map['namespaces']) : null,
      includeCertificate: map['includeCertificate'] ?? true,
      enveloped: map['enveloped'] ?? true,
      xpath: map['xpath'],
    );
  }
}