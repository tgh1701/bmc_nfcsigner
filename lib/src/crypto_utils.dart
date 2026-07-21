import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'dart:convert';
class CryptoUtils {
  /// Băm dữ liệu bằng SHA-256 và đóng gói vào cấu trúc ASN.1 DigestInfo.
  ///
  /// [dataToHash] là dữ liệu gốc cần được băm.
  /// Trả về một `Uint8List` chứa toàn bộ cấu trúc DigestInfo, sẵn sàng để gửi đến thẻ ký.
  static Uint8List createSha256DigestInfo(Uint8List dataToHash) {
    /// Tiền tố ASN.1 cho cấu trúc DigestInfo của SHA-256.
    /// Đây là một giá trị không đổi.
    /// SEQUENCE (30) + Length (21) +
    ///   SEQUENCE (30) + Length (0D) +
    ///     OBJECT IDENTIFIER (06) + Length (09) + OID for sha256 (60 86 48 01 65 03 04 02 01) +
    ///     NULL (05) + Length (00) +
    ///   OCTET STRING (04) + Length (20)
    final _sha256DigestInfoPrefix = [
      0x30,
      0x31,
      0x30,
      0x0d,
      0x06,
      0x09,
      0x60,
      0x86,
      0x48,
      0x01,
      0x65,
      0x03,
      0x04,
      0x02,
      0x01,
      0x05,
      0x00,
      0x04,
      0x20
    ];

    // 1. Băm dữ liệu gốc bằng SHA-256
    final hash = sha256
        .convert(dataToHash)
        .bytes;

    // 2. Nối tiền tố ASN.1 với kết quả băm để tạo thành DigestInfo
    final builder = BytesBuilder();
    builder.add(_sha256DigestInfoPrefix);
    builder.add(hash);

    return builder.toBytes();
  }

  /// Tính toán SHA-256 hash của dữ liệu
  static Uint8List sha256Hash(List<int> data) {
    final digest = sha256.convert(data);
    return Uint8List.fromList(digest.bytes);
  }
  /// Mã hóa Base64
  static String base64Encode(Uint8List data) {
    return base64.encode(data);
  }

  /// Giải mã Base64
  static Uint8List base64Decode(String data) {
    return base64.decode(data);
  }

  /// Chuyển đổi hex string sang byte array
  static Uint8List hexToBytes(String hex) {
    final result = Uint8List(hex.length ~/ 2);
    for (int i = 0; i < hex.length; i += 2) {
      final byte = int.parse(hex.substring(i, i + 2), radix: 16);
      result[i ~/ 2] = byte;
    }
    return result;
  }

  /// Chuyển đổi byte array sang hex string
  static String bytesToHex(Uint8List bytes) {
    return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
}