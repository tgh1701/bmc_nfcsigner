import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'dart:convert';
import 'package:nfcsigner/nfcsigner.dart';
import 'package:open_filex/open_filex.dart';
import 'package:file_picker/file_picker.dart';
import 'package:file_selector/file_selector.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  bool _isSigning = false;
  bool _isLoading = false;
  String _statusMessage = 'Sẵn sàng để ký số';
  String _signatureHex = '';
  ServiceResult? _lastResult;
  String _publicKeyHex = '';
  String _certificateHex = '';
  String _signedXmlContent = '';
  String _decryptResultHex = '';
  String _bytesToHexString(Uint8List bytes) {
    return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
  }
/*
 * Phần giao tiếp dữ liệu Thẻ
 */
  Future<void> _handleSignData() async {
    setState(() {
      _isSigning = true;
      _signatureHex = '';
      _lastResult = null;
      _statusMessage = 'Đang chuẩn bị dữ liệu...';
    });

    final dataToSign = Uint8List.fromList(utf8.encode('Hello, Flutter!'));
    setState(() {
      _statusMessage = 'Đang băm dữ liệu (SHA-256)...';
    });
    // BƯỚC 1: Băm và tạo DigestInfo từ dữ liệu gốc
    final digestInfoToSend = CryptoUtils.createSha256DigestInfo(dataToSign);

    setState(() {
      _statusMessage = 'Đang chờ thẻ...';
    });
    // Gọi plugin và nhận về đối tượng ServiceResult
    final result = await Nfcsigner.generateSignature(
      appletID: 'D27600012401',
      pin: '123456',
      dataToSign: digestInfoToSend,
      keyIndex: 0
    );

    if (mounted) {
      setState(() {
        _isSigning = false;
        _lastResult = result; // Lưu lại kết quả để hiển thị chi tiết

        if (result.isSuccess && result.data != null) {
          _statusMessage = result.message;
          _signatureHex = _bytesToHexString(result.data as Uint8List);
        } else {
          // Xây dựng thông báo lỗi chi tiết
          String errorMessage = 'Lỗi: ${result.message}';
          if (result.sw1 != null && result.sw2 != null) {
            final swHex = '${result.sw1!.toRadixString(16)}${result.sw2!.toRadixString(16)}'.toUpperCase();
            errorMessage += ' (Mã lỗi: $swHex)';
          }
          _statusMessage = errorMessage;
        }
      });
    }
  }
  Future<void> _handleGetPublicKey() async {
    setState(() {
      _isLoading = true;
      _signatureHex = '';
      _publicKeyHex = '';
      _lastResult = null;
      _statusMessage = 'Đang chờ thẻ...';
    });

    final result = await Nfcsigner.getRsaPublicKey(
      appletID: 'D27600012401', // Thay bằng AID của bạn
      keyRole: KeyRole.sig, // Lấy khóa dùng để ký
    );

    if (mounted) {
      setState(() {
        _isLoading = false;
        _lastResult = result;
        if (result.isSuccess && result.data != null) {
          _statusMessage = 'Lấy khóa công khai thành công!';
          _publicKeyHex = _bytesToHexString(result.data as Uint8List);
        } else {
          // Xây dựng thông báo lỗi chi tiết
          String errorMessage = 'Lỗi: ${result.message}';
          if (result.sw1 != null) {
            final swHex = '${result.sw1!.toRadixString(16)}${result.sw2!.toRadixString(16)}'.toUpperCase();
            errorMessage += ' (Mã thẻ: $swHex)';
          }
          _statusMessage = errorMessage;
        }
      });
    }
  }
  // HÀM ĐỂ LẤY CERTIFICATE
  Future<void> _handleGetCertificate() async {
    setState(() {
      _isLoading = true;
      _signatureHex = '';
      _publicKeyHex = '';
      _certificateHex = '';
      _lastResult = null;
      _statusMessage = 'Đang chờ thẻ...';
    });

    final result = await Nfcsigner.getCertificate(
      appletID: 'D27600012401', // Applet ID
      keyRole: KeyRole.sig, // Lấy Ceftificate của Signature
    );

    if (mounted) {
      setState(() {
        _isLoading = false;
        _lastResult = result;
        if (result.isSuccess && result.data != null) {
          _statusMessage = 'Lấy certificate thành công!';
          _certificateHex = _bytesToHexString(result.data as Uint8List);
        } else {
          // Xây dựng thông báo lỗi chi tiết
          String errorMessage = 'Lỗi: ${result.message}';
          if (result.sw1 != null) {
            final swHex = '${result.sw1!.toRadixString(16)}${result.sw2!.toRadixString(16)}'.toUpperCase();
            errorMessage += ' (Mã thẻ: $swHex)';
          }
          _statusMessage = errorMessage;
        }
      });
    }
  }

  // --- HÀM MỚI ĐỂ TẠO VÀ KÝ PDF ---
  Future<void> _handleSignPdf() async {
    setState(() {
      _isLoading = true;
      _clearResults();
      _statusMessage = 'Vui lòng chọn file PDF...';
    });

    // 1. Chọn file
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['pdf'],
      withData: true, // Rất quan trọng: để lấy được nội dung file
    );

    if (result == null || result.files.single.bytes == null) {
      setState(() { _isLoading = false; _statusMessage = 'Đã hủy chọn file.'; });
      return;
    }
    final pdfBytes = result.files.single.bytes!;
    final pdfDigestInfoBytes = CryptoUtils.createSha256DigestInfo(pdfBytes);
    setState(() { _statusMessage = 'Đã chọn file. Vui lòng chạm thẻ để ký...'; });

    // 2. Tạo cấu hình chữ ký (có thể lấy ảnh từ assets hoặc file)
    final signatureConfig = PdfSignatureConfig(
      x: 200.0,           // Vị trí từ trái
      y: 700.0,          // Vị trí từ dưới
      width: 300.0,      // Chiều rộng
      height: 80.0,      // Chiều cao
      pageNumber: 1,     // Trang số 1
      contact: 'info@bmctech.vn',
      signerName: 'Màu Văn Phương',
      signDate: DateTime.now(),
      signatureImage: await _loadSignatureImage(), // Tùy chọn: load ảnh chữ ký
      signatureImageHeight: 50,
      signatureImageWidth: 100,
    );
    // 3. Gọi plugin để ký
    final signResult = await Nfcsigner.signPdf(
      pdfBytes: pdfBytes,
      pdfHashBytes: pdfDigestInfoBytes,
      appletID: 'D27600012401',
      pin: '123456',
      reason: 'Ky nhay tam thoi',
      location: 'Hanoi',
      signatureConfig: signatureConfig,
    );

    // 4. Xử lý kết quả
    if (mounted) {
      setState(() {
        _isLoading = false;
        _lastResult = signResult;
        if (signResult.isSuccess && signResult.data != null) {
          _statusMessage = 'Ký PDF thành công! Đang lưu file...';
          // 4. Lưu file đã ký
          _saveSignedPdf(signResult.data!);
        } else {
          _statusMessage = 'Lỗi: ${signResult.message}';
        }
      });
    }
  }
  // --- PHƯƠNG THỨC SỬ DỤNG file_selector ---
  Future<void> _handleSignXmlWithFileSelector() async {
    setState(() {
      _isLoading = true;
      _clearResults();
      _signedXmlContent = '';
      _statusMessage = 'Vui lòng chọn file XML...';
    });

    try {
      // Sử dụng file_selector - hoạt động tốt hơn trên Android
      final XFile? file = await openFile(
        acceptedTypeGroups: [
          XTypeGroup(
            label: 'XML',
            extensions: ['xml'],
            mimeTypes: ['text/xml', 'application/xml'],
            uniformTypeIdentifiers: ['public.xml'],
          ),
        ],
      );

      if (file == null) {
        setState(() {
          _isLoading = false;
          _statusMessage = 'Đã hủy chọn file.';
        });
        return;
      }

      // Đọc nội dung file
      final xmlContent = await file.readAsString();

      if (kDebugMode) {
        print("File_selector - File path: ${file.path}");
        print("File_selector - File name: ${file.name}");
        print("File_selector - File size: ${(await file.length())} bytes");
      }

      setState(() {
        _statusMessage = 'Đã chọn file XML: ${file.name}. Vui lòng chạm thẻ để ký...';
      });

      final xmlSignatureConfig = XmlSignatureConfig(
        signatureId: 'signature-${DateTime.now().millisecondsSinceEpoch}',
        includeCertificate: true,
        enveloped: true,
        namespaces: {
          'ds': 'http://www.w3.org/2000/09/xmldsig#',
        },
      );

      final signResult = await Nfcsigner.signXml(
        xmlContent: xmlContent,
        appletID: 'D27600012401',
        pin: '123456',
        keyIndex: 0,
        signatureConfig: xmlSignatureConfig,
      );

      if (mounted) {
        setState(() {
          _isLoading = false;
          _lastResult = signResult;
          if (signResult.isSuccess && signResult.data != null) {
            _statusMessage = 'Ký XML thành công!';
            _signedXmlContent = signResult.data!;
            _saveSignedXml(_signedXmlContent);
          } else {
            _statusMessage = 'Lỗi ký XML: ${signResult.message}';
          }
        });
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
        _statusMessage = 'Lỗi khi xử lý XML với file_selector: $e';
      });
      if (kDebugMode) {
        print("Lỗi file_selector: $e");
      }
    }
  }
// --- HÀM MỚI ĐỂ KÝ XML ---
  Future<void> _handleSignXml() async {
    setState(() {
      _isLoading = true;
      _clearResults();
      _signedXmlContent = ''; // Clear previous XML content
      _statusMessage = 'Vui lòng chọn file XML...';
    });

    try {
      // 1. Chọn file XML
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['xml'],
        allowMultiple: false,
        withData: true,
        // Thêm options đặc biệt cho Android
        onFileLoading: (FilePickerStatus status) {
          if (kDebugMode) {
            print("FilePicker Status: $status");
          }
        },
      );

      if (result == null || result.files.single.bytes == null) {
        setState(() {
          _isLoading = false;
          _statusMessage = 'Đã hủy chọn file.';
        });
        return;
      }

      final xmlBytes = result.files.single.bytes!;
      final xmlContent = utf8.decode(xmlBytes);

      setState(() {
        _statusMessage = 'Đã chọn file XML. Vui lòng chạm thẻ để ký...';
      });

      // 2. Tạo cấu hình ký XML
      final xmlSignatureConfig = XmlSignatureConfig(
        signatureId: 'signature-${DateTime.now().millisecondsSinceEpoch}',
        includeCertificate: true,
        enveloped: true,
        namespaces: {
          'ds': 'http://www.w3.org/2000/09/xmldsig#',
        },
      );

      // 3. Gọi plugin để ký XML
      final signResult = await Nfcsigner.signXml(
        xmlContent: xmlContent,
        appletID: 'D27600012401',
        pin: '123456',
        keyIndex: 0,
        signatureConfig: xmlSignatureConfig,
      );

      // 4. Xử lý kết quả
      if (mounted) {
        setState(() {
          _isLoading = false;
          _lastResult = signResult;
          if (signResult.isSuccess && signResult.data != null) {
            _statusMessage = 'Ký XML thành công!';
            _signedXmlContent = signResult.data!;
            // Lưu file XML đã ký
            _saveSignedXml(_signedXmlContent);
          } else {
            _statusMessage = 'Lỗi ký XML: ${signResult.message}';
          }
        });
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
        _statusMessage = 'Lỗi khi xử lý XML: $e';
      });
    }
  }
  // HÀM _saveSignedPdf PHIÊN BẢN MỚI
  Future<void> _saveSignedPdf(Uint8List signedBytes) async {
    try {
      // 1. Lấy thư mục tạm thời của ứng dụng
      final tempDir = await getTemporaryDirectory();
      final filePath = '${tempDir.path}/signed_${DateTime.now().millisecondsSinceEpoch}.pdf';
      final file = File(filePath);

      // 2. Lưu file vào thư mục tạm thời
      await file.writeAsBytes(signedBytes);
      if (kDebugMode) {
        print("Đã lưu file tạm thời tại: $filePath");
      }

      // 3. Dùng open_filex để MỞ file
      final result = await OpenFilex.open(filePath);

      // 4. Cập nhật trạng thái cho người dùng
      setState(() {
        _statusMessage = 'Ký thành công lưu file tại: $filePath';
      });

    } catch (e) {
      setState(() {
        _statusMessage = 'Lỗi khi lưu hoặc mở file: ${e.toString()}';
      });
    }
  }
  // HÀM ĐỂ LƯU FILE XML ĐÃ KÝ
  Future<void> _saveSignedXml(String signedXmlContent) async {
    try {
      // 1. Lấy thư mục tạm thời của ứng dụng
      final tempDir = await getTemporaryDirectory();
      final filePath = '${tempDir.path}/signed_${DateTime.now().millisecondsSinceEpoch}.xml';
      final file = File(filePath);

      // 2. Lưu nội dung XML vào file
      await file.writeAsString(signedXmlContent);
      if (kDebugMode) {
        print("Đã lưu file XML tại: $filePath");
      }

      // 3. Dùng open_filex để MỞ file
      final result = await OpenFilex.open(filePath);

      // 4. Cập nhật trạng thái cho người dùng
      setState(() {
        _statusMessage = 'Ký XML thành công! Đã lưu file tại: $filePath';
      });

    } catch (e) {
      setState(() {
        _statusMessage = 'Lỗi khi lưu hoặc mở file XML: ${e.toString()}';
      });
    }
  }
  // Hàm để xem nội dung XML đã ký (nếu có)
  void _viewSignedXml() {
    if (_signedXmlContent.isEmpty) {
      return;
    }

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Nội dung XML đã ký'),
        content: SizedBox(
          width: double.maxFinite,
          child: SingleChildScrollView(
            child: SelectableText(
              _signedXmlContent,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 10),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Đóng'),
          ),
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _signedXmlContent));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Đã sao chép nội dung XML vào clipboard')),
              );
            },
            child: const Text('Sao chép'),
          ),
        ],
      ),
    );
  }
  // Hàm helper để reset trạng thái hiển thị
  void _clearResults() {
    setState(() {
      _lastResult = null;
    });
  }
  // Hàm tùy chọn để load ảnh chữ ký từ assets
  Future<Uint8List?> _loadSignatureImage() async {
    try {
      final ByteData data = await rootBundle.load('assets/signature.png');
      return data.buffer.asUint8List();
    } catch (e) {
      print('Không thể load ảnh chữ ký: $e');
      return null;
    }
  }

  /// Demo: Get encryption public key (KeyRole.dec)
  Future<void> _handleGetEncPublicKey() async {
    setState(() {
      _isLoading = true;
      _clearResults();
      _statusMessage = 'Đang lấy khóa mã hoá (dec)...';
    });

    final result = await Nfcsigner.getRsaPublicKey(
      appletID: 'D27600012401',
      keyRole: KeyRole.dec,
    );

    if (mounted) {
      setState(() {
        _isLoading = false;
        _lastResult = result;
        if (result.isSuccess && result.data != null) {
          _statusMessage = 'Lấy khóa mã hoá thành công!';
          _publicKeyHex = _bytesToHexString(result.data as Uint8List);
        } else {
          _statusMessage = 'Lỗi: ${result.message}';
        }
      });
    }
  }

  /// Demo: Decrypt data using S-USB hardware
  Future<void> _handleDecryptData() async {
    setState(() {
      _isLoading = true;
      _clearResults();
      _statusMessage = 'Đang giải mã dữ liệu...';
    });

    // Demo: use a test encrypted data (in real use, this would be actual ciphertext)
    // For testing, use a 512-byte block (RSA-4096 ciphertext size)
    final testEncryptedData = Uint8List(512); // All zeros for demo
    for (int i = 0; i < testEncryptedData.length; i++) {
      testEncryptedData[i] = i & 0xFF;
    }

    final result = await Nfcsigner.decryptData(
      appletID: 'D27600012401',
      pin: '123456',
      encryptedData: testEncryptedData,
    );

    if (mounted) {
      setState(() {
        _isLoading = false;
        _lastResult = result;
        if (result.isSuccess && result.data != null) {
          _statusMessage = 'Giải mã thành công! (${result.data!.length} bytes)';
          _decryptResultHex = _bytesToHexString(result.data as Uint8List);
        } else {
          String errorMessage = 'Lỗi giải mã: ${result.message}';
          if (result.sw1 != null) {
            final swHex = '${result.sw1!.toRadixString(16)}${result.sw2!.toRadixString(16)}'.toUpperCase();
            errorMessage += ' (SW: $swHex)';
          }
          _statusMessage = errorMessage;
        }
      });
    }
  }
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Ví dụ Plugin Ký số'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[

              Text(
                _statusMessage,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    color: _lastResult == null ? null : (_lastResult!.isSuccess ? Colors.green.shade800 : Colors.red.shade800)
                ),
              ),
              const SizedBox(height: 32),
              if (_isSigning)
                const Center(child: CircularProgressIndicator())
              else
                ElevatedButton(
                  onPressed: _handleSignData,
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  child: const Text('Bắt đầu Ký'),
                ),
              const SizedBox(height: 12),
              ElevatedButton(
                onPressed: _handleGetPublicKey,
                style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.blueGrey,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                ),
                child: const Text('Lấy Khóa Công Khai RSA'),
              ),
              const SizedBox(height: 12),
              // NÚT BẤM MỚI
              ElevatedButton(
                onPressed: _handleGetCertificate,
                style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.teal,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                ),
                child: const Text('Lấy Certificate'),
              ),
              const SizedBox(height: 16),
              if (_isLoading)
                const Center(child: CircularProgressIndicator())
              else
                Column(
                  children: [
                    ElevatedButton(
                      onPressed: _handleSignPdf,
                      style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.deepPurple,
                          padding: const EdgeInsets.symmetric(vertical: 16)
                      ),
                      child: const Text('Tạo và Ký File PDF Mới'),
                    ),
                    const SizedBox(height: 12),
                    // NÚT KÝ XML MỚI
                    ElevatedButton(
                      onPressed: _handleSignXmlWithFileSelector,
                      style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.orange,
                          padding: const EdgeInsets.symmetric(vertical: 16)
                      ),
                      child: const Text('Ký File XML'),
                    ),
                  ],
                ),
              const SizedBox(height: 12),
              // NÚT LẤY KHÓA MÃ HOÁ
              ElevatedButton(
                onPressed: _handleGetEncPublicKey,
                style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.indigo,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                ),
                child: const Text('Lấy Khóa Mã Hoá (dec)'),
              ),
              const SizedBox(height: 12),
              // NÚT GIẢI MÃ
              ElevatedButton(
                onPressed: _handleDecryptData,
                style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.red.shade700,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                ),
                child: const Text('Demo Giải Mã (Decrypt)'),
              ),
              if (_signatureHex.isNotEmpty)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Chữ ký (Hex):',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.grey.shade200,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: SelectableText(
                        _signatureHex,
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                    ),
                  ],
                ),
              if (_publicKeyHex.isNotEmpty)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Khóa công khai (Hex):', style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(color: Colors.grey.shade200, borderRadius: BorderRadius.circular(8)),
                      child: SelectableText(_publicKeyHex, style: const TextStyle(fontFamily: 'monospace')),
                    ),
                  ],
                ),
              if (_certificateHex.isNotEmpty)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Certificate (Hex):', style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(color: Colors.grey.shade200, borderRadius: BorderRadius.circular(8)),
                      child: SelectableText(_certificateHex, style: const TextStyle(fontFamily: 'monospace')),
                    ),
                  ],
                ),
              // Hiển thị nút xem XML đã ký (nếu có)
              if (_signedXmlContent.isNotEmpty)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const SizedBox(height: 16),
                    Row(
                      children: [
                        const Text('XML đã ký:', style: TextStyle(fontWeight: FontWeight.bold)),
                        const SizedBox(width: 12),
                        ElevatedButton(
                          onPressed: _viewSignedXml,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.green,
                            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                          ),
                          child: const Text('Xem nội dung'),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.green.shade50,
                        border: Border.all(color: Colors.green.shade200),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        'XML đã được ký thành công! (${_signedXmlContent.length} ký tự)',
                        style: TextStyle(color: Colors.green.shade800),
                      ),
                    ),
                  ],
                ),
              // Hiển thị kết quả giải mã (nếu có)
              if (_decryptResultHex.isNotEmpty)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const SizedBox(height: 16),
                    const Text('Kết quả giải mã (Hex):', style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.red.shade50,
                        border: Border.all(color: Colors.red.shade200),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: SelectableText(
                        _decryptResultHex,
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                    ),
                  ],
                ),
            ],
          ),
        ),
      ),
    );
  }
}
