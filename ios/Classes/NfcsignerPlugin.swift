import Flutter
import UIKit
import CoreNFC
import PDFKit
import Security
import CommonCrypto
import CryptoTokenKit

@available(iOS 16.0, *)
class ImageAnnotation: PDFAnnotation {
    var image: UIImage?
    
    override func draw(with box: PDFDisplayBox, in context: CGContext) {
        // Do NOT call super.draw() — it renders default stamp border + X diagonals
        
        guard let image = image, let cgImage = image.cgImage else { return }
        
        context.saveGState()
        context.draw(cgImage, in: self.bounds)
        context.restoreGState()
    }
}

@available(iOS 16.0, *)
public class NfcsignerPlugin: NSObject, FlutterPlugin, NFCTagReaderSessionDelegate {

    var session: NFCTagReaderSession?
    var pendingResult: FlutterResult?
    var pendingCall: FlutterMethodCall?
    
    // USB Card Manager
    private lazy var usbCardManager: UsbCardManager = UsbCardManager()

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "nfcsigner", binaryMessenger: registrar.messenger())
        let instance = NfcsignerPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        self.pendingCall = call
        self.pendingResult = result
        
        // Ưu tiên USB nếu có reader được kết nối
        if usbCardManager.isReaderConnected() {
            print("🔌 [USB] Phát hiện đầu đọc USB, sử dụng USB path")
            handleUsbRequest(call: call, result: result)
            return
        }
        
        // Fallback về NFC
        print("📡 [NFC] Không có USB reader, sử dụng NFC path")
        handleNfcRequest(call: call, result: result)
    }
    
    // MARK: - USB Request Handling
    
    private func handleUsbRequest(call: FlutterMethodCall, result: @escaping FlutterResult) {
        usbCardManager.connect { [weak self] success, errorMessage in
            guard let self = self else { return }
            
            if !success {
                // Nếu USB không kết nối được, fallback về NFC
                print("⚠️ [USB] Kết nối thất bại: \(errorMessage ?? "Unknown"), fallback về NFC")
                self.handleNfcRequest(call: call, result: result)
                return
            }
            
            // Xử lý command qua USB
            switch call.method {
            case "generateSignature":
                self.handleGenerateSignatureViaUsb(call: call, result: result)
            case "getRsaPublicKey":
                self.handleGetRsaPublicKeyViaUsb(call: call, result: result)
            case "getCertificate":
                self.handleGetCertificateViaUsb(call: call, result: result)
            case "signPdf":
                self.handleSignPdfViaUsb(call: call, result: result)
            case "generateXMLSignature":
                self.handleGenerateXMLSignatureViaUsb(call: call, result: result)
            case "decryptData":
                self.handleDecryptDataViaUsb(call: call, result: result)
            default:
                self.usbCardManager.disconnect()
                result(FlutterMethodNotImplemented)
            }
        }
    }
    
    // MARK: - USB Operation Handlers
    
    private func handleGenerateSignatureViaUsb(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let dataToSign = arguments["dataToSign"] as? FlutterStandardTypedData,
              let keyIndex = arguments["keyIndex"] as? Int else {
            usbCardManager.disconnect()
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        let aidData = dataWithHexString(hex: appletIDHex)
        
        // Step 1: Select Applet
        usbCardManager.selectApplet(aid: aidData) { [weak self] success, sw1, sw2, error in
            guard let self = self else { return }
            
            if !success {
                self.usbCardManager.disconnect()
                result(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                return
            }
            
            // Step 2: Verify PIN
            self.usbCardManager.verifyPin(pin: pin) { success, sw1, sw2, error in
                if !success {
                    self.usbCardManager.disconnect()
                    result(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    return
                }
                
                // Step 3: Generate Signature
                self.usbCardManager.generateSignature(dataToSign: dataToSign.data, keyIndex: keyIndex) { signature, sw1, sw2, error in
                    self.usbCardManager.disconnect()
                    
                    if let signature = signature {
                        result(FlutterStandardTypedData(bytes: signature))
                    } else {
                        result(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Ký số thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    }
                }
            }
        }
    }
    
    private func handleGetRsaPublicKeyViaUsb(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let keyRole = arguments["keyRole"] as? String else {
            usbCardManager.disconnect()
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        let aidData = dataWithHexString(hex: appletIDHex)
        
        usbCardManager.selectApplet(aid: aidData) { [weak self] success, sw1, sw2, error in
            guard let self = self else { return }
            
            if !success {
                self.usbCardManager.disconnect()
                result(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                return
            }
            
            self.usbCardManager.getRsaPublicKey(keyRole: keyRole) { publicKey, sw1, sw2, error in
                self.usbCardManager.disconnect()
                
                if let publicKey = publicKey {
                    result(FlutterStandardTypedData(bytes: publicKey))
                } else {
                    result(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Không thể lấy khóa công khai.", details: ["sw1": sw1, "sw2": sw2]))
                }
            }
        }
    }
    
    private func handleGetCertificateViaUsb(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let keyRole = arguments["keyRole"] as? String else {
            usbCardManager.disconnect()
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        let aidData = dataWithHexString(hex: appletIDHex)
        
        usbCardManager.selectApplet(aid: aidData) { [weak self] success, sw1, sw2, error in
            guard let self = self else { return }
            
            if !success {
                self.usbCardManager.disconnect()
                result(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                return
            }
            
            self.usbCardManager.getCertificate(keyRole: keyRole) { certificate, sw1, sw2, error in
                self.usbCardManager.disconnect()
                
                if let certificate = certificate {
                    result(FlutterStandardTypedData(bytes: certificate))
                } else {
                    result(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Không thể lấy certificate.", details: ["sw1": sw1, "sw2": sw2]))
                }
            }
        }
    }
    
    private func handleSignPdfViaUsb(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let pdfBytes = arguments["pdfBytes"] as? FlutterStandardTypedData,
              let hashedBytes = arguments["pdfHashBytes"] as? FlutterStandardTypedData,
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let keyIndex = arguments["keyIndex"] as? Int,
              let reason = arguments["reason"] as? String,
              let location = arguments["location"] as? String else {
            usbCardManager.disconnect()
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        let signatureConfig = arguments["signatureConfig"] as? [String: Any]
        let x = signatureConfig?["x"] as? Double ?? 36.0
        let y = signatureConfig?["y"] as? Double ?? 700.0
        let width = signatureConfig?["width"] as? Double ?? 200.0
        let height = signatureConfig?["height"] as? Double ?? 50.0
        let pageNumber = signatureConfig?["pageNumber"] as? Int ?? 1
        let signatureImageBytes = signatureConfig?["signatureImage"] as? FlutterStandardTypedData
        let signatureImageWidth = signatureConfig?["signatureImageWidth"] as? Double ?? 80.0
        let signatureImageHeight = signatureConfig?["signatureImageHeight"] as? Double ?? 30.0
        let contact = signatureConfig?["contact"] as? String
        let signerName = signatureConfig?["signerName"] as? String
        
        let aidData = dataWithHexString(hex: appletIDHex)
        
        // Select Applet -> Verify PIN -> Get Certificate -> Sign
        usbCardManager.selectApplet(aid: aidData) { [weak self] success, sw1, sw2, error in
            guard let self = self else { return }
            
            if !success {
                self.usbCardManager.disconnect()
                result(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                return
            }
            
            self.usbCardManager.verifyPin(pin: pin) { success, sw1, sw2, error in
                if !success {
                    self.usbCardManager.disconnect()
                    result(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    return
                }
                
                // Get certificate
                self.usbCardManager.getCertificate(keyRole: "sig") { certificateData, sw1, sw2, error in
                    guard let certificateData = certificateData else {
                        self.usbCardManager.disconnect()
                        result(FlutterError(code: "CERTIFICATE_ERROR", message: "Không thể lấy certificate.", details: nil))
                        return
                    }
                    
                    // Sign the hash
                    self.usbCardManager.generateSignature(dataToSign: hashedBytes.data, keyIndex: keyIndex) { signatureData, sw1, sw2, error in
                        self.usbCardManager.disconnect()
                        
                        guard let signatureData = signatureData else {
                            result(FlutterError(code: "SIGNING_ERROR", message: "Ký số thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                            return
                        }
                        
                        // Create signed PDF
                        do {
                            let signedPdfData = try self.createSignedPdf(
                                originalPdfData: pdfBytes.data,
                                signature: signatureData,
                                certificate: certificateData,
                                reason: reason,
                                location: location,
                                x: x,
                                y: y,
                                width: width,
                                height: height,
                                pageNumber: pageNumber,
                                signatureImageData: signatureImageBytes?.data,
                                signatureImageWidth: signatureImageWidth,
                                signatureImageHeight: signatureImageHeight,
                                contact: contact,
                                signerName: signerName
                            )
                            result(FlutterStandardTypedData(bytes: signedPdfData))
                        } catch {
                            result(FlutterError(code: "PDF_CREATION_ERROR", message: "Lỗi khi tạo PDF đã ký: \(error.localizedDescription)", details: nil))
                        }
                    }
                }
            }
        }
    }
    
    private func handleGenerateXMLSignatureViaUsb(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let dataToSign = arguments["dataToSign"] as? FlutterStandardTypedData,
              let keyIndex = arguments["keyIndex"] as? Int else {
            usbCardManager.disconnect()
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        let aidData = dataWithHexString(hex: appletIDHex)
        
        usbCardManager.selectApplet(aid: aidData) { [weak self] success, sw1, sw2, error in
            guard let self = self else { return }
            
            if !success {
                self.usbCardManager.disconnect()
                result(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                return
            }
            
            self.usbCardManager.verifyPin(pin: pin) { success, sw1, sw2, error in
                if !success {
                    self.usbCardManager.disconnect()
                    result(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    return
                }
                
                // Generate signature
                self.usbCardManager.generateSignature(dataToSign: dataToSign.data, keyIndex: keyIndex) { signatureData, sw1, sw2, error in
                    guard let signatureData = signatureData else {
                        self.usbCardManager.disconnect()
                        result(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Ký số thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                        return
                    }
                    
                    // Get certificate
                    self.usbCardManager.getCertificate(keyRole: "sig") { certificateData, sw1, sw2, error in
                        self.usbCardManager.disconnect()
                        
                        guard let certificateData = certificateData else {
                            result(FlutterError(code: "CERTIFICATE_ERROR", message: "Không thể lấy certificate.", details: nil))
                            return
                        }
                        
                        let resultDict: [String: Any] = [
                            "certificate": certificateData.base64EncodedString(),
                            "signature": signatureData.base64EncodedString()
                        ]
                        
                        guard let resultData = try? JSONSerialization.data(withJSONObject: resultDict) else {
                            result(FlutterError(code: "RESULT_ERROR", message: "Lỗi đóng gói kết quả.", details: nil))
                            return
                        }
                        
                        result(FlutterStandardTypedData(bytes: resultData))
                    }
                }
            }
        }
    }
    
    private func handleDecryptDataViaUsb(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let encryptedData = arguments["encryptedData"] as? FlutterStandardTypedData else {
            usbCardManager.disconnect()
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        let aidData = dataWithHexString(hex: appletIDHex)
        
        // Step 1: Select Applet
        usbCardManager.selectApplet(aid: aidData) { [weak self] success, sw1, sw2, error in
            guard let self = self else { return }
            
            if !success {
                self.usbCardManager.disconnect()
                result(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                return
            }
            
            // Step 2: Verify PIN (mode 82 for decryption)
            self.usbCardManager.verifyPinForDecrypt(pin: pin) { success, sw1, sw2, error in
                if !success {
                    self.usbCardManager.disconnect()
                    result(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    return
                }
                
                // Step 3: PSO:DECIPHER with command chaining
                self.usbCardManager.decryptData(encryptedData: encryptedData.data) { decryptedData, sw1, sw2, error in
                    self.usbCardManager.disconnect()
                    
                    if let decryptedData = decryptedData {
                        result(FlutterStandardTypedData(bytes: decryptedData))
                    } else {
                        result(FlutterError(code: "DECRYPT_ERROR", message: "Giải mã thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    }
                }
            }
        }
    }
    
    // MARK: - NFC Request Handling
    
    private func handleNfcRequest(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard NFCNDEFReaderSession.readingAvailable else {
            result(FlutterError(code: "NFC_UNAVAILABLE", message: "Thiết bị không hỗ trợ NFC.", details: nil))
            return
        }

        // LUÔN chạy trên main thread
        DispatchQueue.main.async {
            self.session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
            self.session?.alertMessage = "Giữ thẻ của bạn gần đầu điện thoại."

            // Thêm delay nhỏ để đảm bảo session được tạo hoàn toàn
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                self.session?.begin()
            }
        }
    }

    // MARK: - NFCTagReaderSessionDelegate

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if let nfcError = error as? NFCReaderError, nfcError.code != .readerSessionInvalidationErrorUserCanceled {
            pendingResult?(FlutterError(code: "COMMUNICATION_ERROR", message: error.localizedDescription, details: nil))
        }
        cleanup()
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard tags.count == 1 else {
            session.invalidate(errorMessage: "Phát hiện nhiều thẻ. Vui lòng chỉ sử dụng một thẻ.")
            pendingResult?(FlutterError(code: "COMMUNICATION_ERROR", message: "Phát hiện nhiều thẻ.", details: nil))
            cleanup()
            return
        }

        let tag = tags.first!
        session.connect(to: tag) { (error: Error?) in
            if error != nil {
                session.invalidate(errorMessage: "Không thể kết nối với thẻ.")
                self.pendingResult?(FlutterError(code: "COMMUNICATION_ERROR", message: "Không thể kết nối với thẻ.", details: nil))
                self.cleanup()
                return
            }

            guard case let .iso7816(iso7816Tag) = tag else {
                session.invalidate(errorMessage: "Thẻ không tương thích (ISO7816).")
                self.pendingResult?(FlutterError(code: "TAG_NOT_SUPPORTED", message: "Thẻ không tương thích (ISO7816).", details: nil))
                self.cleanup()
                return
            }

            if self.pendingCall?.method == "generateSignature" {
                self.handleGenerateSignature(tag: iso7816Tag, session: session)
            } else if self.pendingCall?.method == "getRsaPublicKey" {
                self.handleGetRsaPublicKey(tag: iso7816Tag, session: session)
            } else if self.pendingCall?.method == "getCertificate" {
                self.handleGetCertificate(tag: iso7816Tag, session: session)
            } else if self.pendingCall?.method == "signPdf" {
                self.handleSignPdf(tag: iso7816Tag, session: session)
            } else if self.pendingCall?.method == "generateXMLSignature" {
                self.handleGenerateXMLSignature(tag: iso7816Tag, session: session)
            } else if self.pendingCall?.method == "decryptData" {
                self.handleDecryptData(tag: iso7816Tag, session: session)
            }
            else {
                session.invalidate(errorMessage: "Lệnh không được hỗ trợ.")
                self.pendingResult?(FlutterMethodNotImplemented)
                self.cleanup()
            }
        }
    }

    // MARK: - NFC Logic Handlers

    private func handleGenerateSignature(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let dataToSign = arguments["dataToSign"] as? FlutterStandardTypedData,
              let keyIndex = arguments["keyIndex"] as? Int else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)
        let verifyAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x20, p1Parameter: 0x00, p2Parameter: 0x81, data: Data(pin.utf8), expectedResponseLength: -1)

        let p2Sign: UInt8 = {
            switch keyIndex {
            case 1: return 0x9B
            case 2: return 0x9C
            default: return 0x9A
            }
        }()

        let signAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x2A, p1Parameter: 0x9E, p2Parameter: p2Sign, data: dataToSign.data, expectedResponseLength: 256)

        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }

            self.sendCommandAndGetResponse(tag: tag, apdu: verifyAPDU) { (_, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Xác thực PIN thất bại.")
                    self.pendingResult?(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                self.sendCommandAndGetResponse(tag: tag, apdu: signAPDU) { (responseData, sw1, sw2, error) in
                    guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                        session.invalidate(errorMessage: "Ký số thất bại.")
                        self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Ký số thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                        self.cleanup()
                        return
                    }

                    session.alertMessage = "Ký thành công!"
                    session.invalidate()
                    self.pendingResult?(FlutterStandardTypedData(bytes: responseData))
                    self.cleanup()
                }
            }
        }
    }

    private func handleGetRsaPublicKey(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let keyRole = arguments["keyRole"] as? String else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)

        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }

            var apduData: Data
            switch keyRole {
            case "sig": apduData = Data([0xB6, 0x00])
            case "dec": apduData = Data([0xB8, 0x00])
            case "aut": apduData = Data([0xA4, 0x00])
            case "sm": apduData = Data([0xA6, 0x00])
            default:
                session.invalidate(errorMessage: "Vai trò khóa không hợp lệ.")
                self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Vai trò khóa không hợp lệ: \(keyRole)", details: nil))
                self.cleanup()
                return
            }

            let getPubKeyAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x47, p1Parameter: 0x81, p2Parameter: 0x00, data: apduData, expectedResponseLength: 256)

            self.sendCommandAndGetResponse(tag: tag, apdu: getPubKeyAPDU) { (responseData, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Không thể lấy khóa công khai.")
                    self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Không thể lấy khóa công khai.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                session.alertMessage = "Lấy khóa thành công!"
                session.invalidate()
                self.pendingResult?(FlutterStandardTypedData(bytes: responseData))
                self.cleanup()
            }
        }
    }

    private func handleGetCertificate(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let keyRole = arguments["keyRole"] as? String else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)

        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }

            var selectCertData: Data
            switch keyRole {
            case "sig": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
            case "dec": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
            case "aut": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
            case "sm": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
            default:
                session.invalidate(errorMessage: "Vai trò khóa không hợp lệ.")
                self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Vai trò khóa không hợp lệ: \(keyRole)", details: nil))
                self.cleanup()
                return
            }

            let selectCertAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA5, p1Parameter: 0x02, p2Parameter: 0x04, data: selectCertData, expectedResponseLength: 256)

            self.sendCommandAndGetResponse(tag: tag, apdu: selectCertAPDU) { (_, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Không thể chọn dữ liệu Certificate.")
                    self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Không thể chọn dữ liệu Certificate.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                let getCertAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xCA, p1Parameter: 0x7F, p2Parameter: 0x21, data: Data(), expectedResponseLength: 2048)

                self.sendCommandAndGetResponse(tag: tag, apdu: getCertAPDU) { (responseData, sw1, sw2, error) in
                    guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                        session.invalidate(errorMessage: "Không thể lấy certificate.")
                        self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Không thể lấy certificate.", details: ["sw1": sw1, "sw2": sw2]))
                        self.cleanup()
                        return
                    }

                    session.alertMessage = "Lấy certificate thành công!"
                    session.invalidate()
                    self.pendingResult?(FlutterStandardTypedData(bytes: responseData))
                    self.cleanup()
                }
            }
        }
    }

    // MARK: - PDF Signing Implementation

    private func handleSignPdf(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let pdfBytes = arguments["pdfBytes"] as? FlutterStandardTypedData,
              let hashedBytes = arguments["pdfHashBytes"] as? FlutterStandardTypedData,
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let keyIndex = arguments["keyIndex"] as? Int,
              let reason = arguments["reason"] as? String,
              let location = arguments["location"] as? String else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        let signatureConfig = arguments["signatureConfig"] as? [String: Any]
        let x = signatureConfig?["x"] as? Double ?? 36.0
        let y = signatureConfig?["y"] as? Double ?? 700.0
        let width = signatureConfig?["width"] as? Double ?? 200.0
        let height = signatureConfig?["height"] as? Double ?? 50.0
        let pageNumber = signatureConfig?["pageNumber"] as? Int ?? 1
        let signatureImageBytes = signatureConfig?["signatureImage"] as? FlutterStandardTypedData
        let signatureImageWidth = signatureConfig?["signatureImageWidth"] as? Double ?? 80.0
        let signatureImageHeight = signatureConfig?["signatureImageHeight"] as? Double ?? 30.0
        let contact = signatureConfig?["contact"] as? String
        let signerName = signatureConfig?["signerName"] as? String

        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)
        let verifyAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x20, p1Parameter: 0x00, p2Parameter: 0x81, data: Data(pin.utf8), expectedResponseLength: -1)

        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }

            self.sendCommandAndGetResponse(tag: tag, apdu: verifyAPDU) { (_, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Xác thực PIN thất bại.")
                    self.pendingResult?(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                // Lấy certificate từ thẻ
                self.getCertificateFromCard(tag: tag) { certificateData in
                    guard let certificateData = certificateData else {
                        session.invalidate(errorMessage: "Không thể lấy certificate từ thẻ.")
                        self.pendingResult?(FlutterError(code: "CERTIFICATE_ERROR", message: "Không thể lấy certificate từ thẻ.", details: nil))
                        self.cleanup()
                        return
                    }

                    // Tính hash của PDF và ký
                    self.signPdfWithDigitalSignature(
                        tag: tag,
                        pdfData: pdfBytes.data,
                        hashedDigest: hashedBytes.data,
                        certificateData: certificateData,
                        keyIndex: keyIndex,
                        reason: reason,
                        location: location,
                        x: x,
                        y: y,
                        width: width,
                        height: height,
                        pageNumber: pageNumber,
                        signatureImageData: signatureImageBytes?.data,
                        signatureImageWidth: signatureImageWidth,
                        signatureImageHeight: signatureImageHeight,
                        contact: contact,
                        signerName: signerName,
                        session: session
                    )
                }
            }
        }
    }

    private func handleGenerateXMLSignature(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let dataToSign = arguments["dataToSign"] as? FlutterStandardTypedData,
              let keyIndex = arguments["keyIndex"] as? Int else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)
        let verifyAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x20, p1Parameter: 0x00, p2Parameter: 0x81, data: Data(pin.utf8), expectedResponseLength: -1)

        let p2Sign: UInt8 = {
            switch keyIndex {
            case 1: return 0x9B
            case 2: return 0x9C
            default: return 0x9A
            }
        }()

        let signAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x2A, p1Parameter: 0x9E, p2Parameter: p2Sign, data: dataToSign.data, expectedResponseLength: 256)

        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }
                self.sendCommandAndGetResponse(tag: tag, apdu: verifyAPDU) { (_, sw1, sw2, error) in
                    guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                        session.invalidate(errorMessage: "Xác thực PIN thất bại.")
                        self.pendingResult?(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                        self.cleanup()
                        return
                    }

                    self.sendCommandAndGetResponse(tag: tag, apdu: signAPDU) { (signatureData, sw1, sw2, error) in
                        guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                            session.invalidate(errorMessage: "Ký số thất bại.")
                            self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Ký số thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                            self.cleanup()
                            return
                        }
                    // Lấy certificate từ thẻ
                    self.getCertificateFromCard(tag: tag) { certificateData in
                        guard let certificateData = certificateData else {
                            session.invalidate(errorMessage: "Không thể lấy certificate từ thẻ.")
                            self.pendingResult?(FlutterError(code: "CERTIFICATE_ERROR", message: "Không thể lấy certificate từ thẻ.", details: nil))
                            self.cleanup()
                            return
                        }
                        let result: [String: Any] = [
                            "certificate": certificateData.base64EncodedString(),
                            "signature": signatureData.base64EncodedString()
                       ]
                       // Chuyển result thành FlutterStandardTypedData
                        guard let resultData = try? JSONSerialization.data(withJSONObject: result) else {
                                       session.invalidate(errorMessage: "Lỗi đóng gói kết quả.")
                                       self.pendingResult?(FlutterError(code: "RESULT_ERROR", message: "Lỗi đóng gói kết quả.", details: nil))
                                       self.cleanup()
                                       return
                        }
                        session.alertMessage = "Ký thành công!"
                        session.invalidate()
                        self.pendingResult?(FlutterStandardTypedData(bytes: resultData))
                        self.cleanup()
                    }
                }
            }
        }
    }

    private func handleDecryptData(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let encryptedData = arguments["encryptedData"] as? FlutterStandardTypedData else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)
        // VERIFY PIN mode 0x82 for decryption
        let verifyAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x20, p1Parameter: 0x00, p2Parameter: 0x82, data: Data(pin.utf8), expectedResponseLength: -1)

        // Build decipher data: padding indicator (0x00) + ciphertext
        var decipherData = Data([0x00])
        decipherData.append(encryptedData.data)

        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }

            self.sendCommandAndGetResponse(tag: tag, apdu: verifyAPDU) { (_, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Xác thực PIN thất bại.")
                    self.pendingResult?(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                // PSO:DECIPHER with command chaining (RSA-4096: 513 bytes → 3 chunks)
                self.sendChainedDecipherNfc(tag: tag, data: decipherData, session: session)
            }
        }
    }

    /// Send PSO:DECIPHER via NFC with command chaining
    ///
    /// Splits data into 255-byte chunks. Intermediate chunks use CLA=0x10,
    /// final chunk uses CLA=0x00 with Le=256.
    private func sendChainedDecipherNfc(tag: NFCISO7816Tag, data: Data, session: NFCTagReaderSession) {
        let maxChunkSize = 255
        var chunks: [Data] = []
        var offset = 0
        while offset < data.count {
            let end = min(offset + maxChunkSize, data.count)
            chunks.append(data[offset..<end])
            offset = end
        }

        func sendChunk(index: Int) {
            guard index < chunks.count else {
                session.invalidate(errorMessage: "Giải mã thất bại.")
                self.pendingResult?(FlutterError(code: "DECRYPT_ERROR", message: "No chunks to send.", details: nil))
                self.cleanup()
                return
            }

            let chunk = chunks[index]
            let isLast = (index == chunks.count - 1)
            let cla: UInt8 = isLast ? 0x00 : 0x10
            let expectedLen: Int = isLast ? 256 : -1

            let apdu = NFCISO7816APDU(instructionClass: cla, instructionCode: 0x2A, p1Parameter: 0x80, p2Parameter: 0x86, data: chunk, expectedResponseLength: expectedLen)

            if isLast {
                // Final chunk — expect decrypted data response
                self.sendCommandAndGetResponse(tag: tag, apdu: apdu) { (responseData, sw1, sw2, error) in
                    guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                        session.invalidate(errorMessage: "Giải mã thất bại.")
                        self.pendingResult?(FlutterError(code: "DECRYPT_ERROR", message: "Giải mã thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                        self.cleanup()
                        return
                    }

                    session.alertMessage = "Giải mã thành công!"
                    session.invalidate()
                    self.pendingResult?(FlutterStandardTypedData(bytes: responseData))
                    self.cleanup()
                }
            } else {
                // Intermediate chunk — expect 9000 acknowledgment
                self.sendCommandAndGetResponse(tag: tag, apdu: apdu) { (_, sw1, sw2, error) in
                    guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                        session.invalidate(errorMessage: "Giải mã thất bại (command chaining).")
                        self.pendingResult?(FlutterError(code: "DECRYPT_ERROR", message: "Command chaining thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                        self.cleanup()
                        return
                    }

                    // Send next chunk
                    sendChunk(index: index + 1)
                }
            }
        }

        sendChunk(index: 0)
    }

    private func getCertificateFromCard(tag: NFCISO7816Tag, completion: @escaping (Data?) -> Void) {
        let keyRole = "sig"

        let selectCertData: Data
        switch keyRole {
        case "sig": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
        case "dec": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
        case "aut": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
        case "sm": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
        default:
            completion(nil)
            return
        }

        let selectCertAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA5, p1Parameter: 0x02, p2Parameter: 0x04, data: selectCertData, expectedResponseLength: 256)

        self.sendCommandAndGetResponse(tag: tag, apdu: selectCertAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                completion(nil)
                return
            }

            let getCertAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xCA, p1Parameter: 0x7F, p2Parameter: 0x21, data: Data(), expectedResponseLength: 2048)

            self.sendCommandAndGetResponse(tag: tag, apdu: getCertAPDU) { (responseData, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    completion(nil)
                    return
                }
                completion(responseData)
            }
        }
    }

    private func signPdfWithDigitalSignature(
        tag: NFCISO7816Tag,
        pdfData: Data,
        hashedDigest: Data,
        certificateData: Data,
        keyIndex: Int,
        reason: String,
        location: String,
        x: Double,
        y: Double,
        width: Double,
        height: Double,
        pageNumber: Int,
        signatureImageData: Data?,
        signatureImageWidth: Double,
        signatureImageHeight: Double,
        contact: String?,
        signerName: String?,
        session: NFCTagReaderSession
    ) {
        do {
            let digestInfo = hashedDigest

            let p2Sign: UInt8 = {
                switch keyIndex {
                case 1: return 0x9B
                case 2: return 0x9C
                default: return 0x9A
                }
            }()

            let signAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x2A, p1Parameter: 0x9E, p2Parameter: p2Sign, data: digestInfo, expectedResponseLength: 256)

            self.sendCommandAndGetResponse(tag: tag, apdu: signAPDU) { (signatureData, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Ký số thất bại.")
                    self.pendingResult?(FlutterError(code: "SIGNING_ERROR", message: "Ký số thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                do {
                    let signedPdfData = try self.createSignedPdf(
                        originalPdfData: pdfData,
                        signature: signatureData,
                        certificate: certificateData,
                        reason: reason,
                        location: location,
                        x: x,
                        y: y,
                        width: width,
                        height: height,
                        pageNumber: pageNumber,
                        signatureImageData: signatureImageData,
                        signatureImageWidth: signatureImageWidth,
                        signatureImageHeight: signatureImageHeight,
                        contact: contact,
                        signerName: signerName
                    )

                    session.alertMessage = "PDF đã được ký số thành công!"
                    session.invalidate()
                    self.pendingResult?(FlutterStandardTypedData(bytes: signedPdfData))
                    self.cleanup()

                } catch {
                    session.invalidate(errorMessage: "Lỗi khi tạo PDF đã ký: \(error.localizedDescription)")
                    self.pendingResult?(FlutterError(code: "PDF_CREATION_ERROR", message: "Lỗi khi tạo PDF đã ký: \(error.localizedDescription)", details: nil))
                    self.cleanup()
                }
            }

        } catch {
            session.invalidate(errorMessage: "Lỗi khi xử lý PDF: \(error.localizedDescription)")
            self.pendingResult?(FlutterError(code: "PDF_PROCESSING_ERROR", message: "Lỗi khi xử lý PDF: \(error.localizedDescription)", details: nil))
            self.cleanup()
        }
    }

    // MARK: - PDF Processing Functions

    private func calculateSHA256(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    private enum HashAlgorithm {
        case sha256
        case sha1

        var oid: [UInt8] {
            switch self {
            case .sha256: return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] // 2.16.840.1.101.3.4.2.1
            case .sha1: return [0x2B, 0x0E, 0x03, 0x02, 0x1A] // 1.3.14.3.2.26
            }
        }

        var name: String {
            switch self {
            case .sha256: return "sha256"
            case .sha1: return "sha1"
            }
        }
    }

    private func createDigestInfo(hash: Data, hashAlgorithm: HashAlgorithm) -> Data {
        var digestInfo = Data()
        digestInfo.append(0x30)
        let sequenceLengthIndex = digestInfo.count
        digestInfo.append(0x00)
        digestInfo.append(0x30)
        let algorithmOID: [UInt8] = hashAlgorithm.oid
        digestInfo.append(0x06)
        digestInfo.append(UInt8(algorithmOID.count))
        digestInfo.append(contentsOf: algorithmOID)
        digestInfo.append(0x05)
        digestInfo.append(0x00)
        digestInfo.append(0x04)
        digestInfo.append(UInt8(hash.count))
        digestInfo.append(contentsOf: hash)
        let sequenceLength = digestInfo.count - sequenceLengthIndex - 1
        digestInfo[sequenceLengthIndex] = UInt8(sequenceLength)
        return digestInfo
    }

private func createSignedPdf(
    originalPdfData: Data,
    signature: Data,
    certificate: Data,
    reason: String,
    location: String,
    x: Double,
    y: Double,
    width: Double,
    height: Double,
    pageNumber: Int,
    signatureImageData: Data?,
    signatureImageWidth: Double,
    signatureImageHeight: Double,
    contact: String?,
    signerName: String?
) throws -> Data {
    guard let pdfDocument = PDFDocument(data: originalPdfData) else {
        throw NSError(domain: "PDFError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Không thể đọc PDF data"])
    }

    let pageIndex = min(max(pageNumber - 1, 0), pdfDocument.pageCount - 1)
    guard let page = pdfDocument.page(at: pageIndex) else {
        throw NSError(domain: "PDFError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Không thể tìm thấy trang PDF"])
    }

    let bounds = CGRect(x: x, y: y, width: width, height: height)

    // Calculate layout: image left column, text right column
    var textBounds = bounds
    if let signatureImageData = signatureImageData,
       let image = UIImage(data: signatureImageData) {
        let imgWidth = signatureImageWidth
        let imgHeight = signatureImageHeight

        // Image annotation — left column, vertically centered
        let imgY = bounds.minY + (bounds.height - imgHeight) / 2.0
        let imageBounds = CGRect(x: bounds.minX + 2, y: imgY,
                                 width: imgWidth, height: imgHeight)

        let imageAnnotation = ImageAnnotation(bounds: imageBounds, forType: .stamp, withProperties: nil)
        imageAnnotation.image = image
        page.addAnnotation(imageAnnotation)

        // Text starts in right column
        let textX = bounds.minX + imgWidth + 8
        let textWidth = bounds.width - imgWidth - 10
        textBounds = CGRect(x: textX, y: bounds.minY, width: textWidth, height: bounds.height)
    }

    let watermarkInfo = """
    Người ký: \(signerName ?? "Unknown")
    Lý do: \(reason)
    Địa điểm: \(location)
    Thời gian: \(Date())
    \(contact != nil ? "Liên hệ: \(contact!)" : "")
    """

    let watermarkAnnotation = PDFAnnotation(bounds: textBounds, forType: .freeText, withProperties: nil)
    watermarkAnnotation.contents = watermarkInfo
    watermarkAnnotation.color = UIColor.clear
    watermarkAnnotation.font = UIFont.systemFont(ofSize: 12)
    watermarkAnnotation.fontColor = UIColor.blue
    watermarkAnnotation.border = PDFBorder()
    watermarkAnnotation.border?.lineWidth = 1.0
    watermarkAnnotation.border?.style = .solid

    page.addAnnotation(watermarkAnnotation)

    guard let signedPdfData = pdfDocument.dataRepresentation() else {
        throw NSError(domain: "PDFError", code: 3, userInfo: [NSLocalizedDescriptionKey: "Không thể tạo PDF đã ký"])
    }

    return signedPdfData
}

    // MARK: - Helper Functions

    private func sendCommandAndGetResponse(
        tag: NFCISO7816Tag,
        apdu: NFCISO7816APDU,
        completion: @escaping (Data, UInt8, UInt8, Error?) -> Void
    ) {
        var accumulatedData = Data()
        func recursiveSend(currentApdu: NFCISO7816APDU) {
            tag.sendCommand(apdu: currentApdu) { (responseData, sw1, sw2, error) in
                if let error = error {
                    completion(Data(), 0, 0, error)
                    return
                }

                accumulatedData.append(responseData)

                if sw1 == 0x61 {
                    let getResponseApdu = NFCISO7816APDU(
                        instructionClass: 0x00, instructionCode: 0xC0,
                        p1Parameter: 0x00, p2Parameter: 0x00,
                        data: Data(), expectedResponseLength: Int(sw2)
                    )
                    recursiveSend(currentApdu: getResponseApdu)
                } else {
                    completion(accumulatedData, sw1, sw2, nil)
                }
            }
        }
        recursiveSend(currentApdu: apdu)
    }

    private func cleanup() {
        self.pendingCall = nil
        self.pendingResult = nil
        self.session = nil
    }

    func dataWithHexString(hex: String) -> Data {
        var hex = hex
        var data = Data()
        while(hex.count > 0) {
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let c = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            var ch: UInt64 = 0
            Scanner(string: c).scanHexInt64(&ch)
            var char = UInt8(ch)
            data.append(&char, count: 1)
        }
        return data
    }
}