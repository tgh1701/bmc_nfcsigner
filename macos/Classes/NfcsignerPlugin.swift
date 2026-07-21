import Cocoa
import FlutterMacOS
import CryptoTokenKit

public class NfcsignerPlugin: NSObject, FlutterPlugin {
    
    private let usbCardManager = MacUsbCardManager()
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "nfcsigner", binaryMessenger: registrar.messenger)
        let instance = NfcsignerPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "getPlatformVersion":
            result("macOS " + ProcessInfo.processInfo.operatingSystemVersionString)
        case "generateSignature":
            handleGenerateSignature(call: call, result: result)
        case "getRsaPublicKey":
            handleGetRsaPublicKey(call: call, result: result)
        case "getCertificate":
            handleGetCertificate(call: call, result: result)
        case "decryptData":
            handleDecryptData(call: call, result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    // MARK: - Handlers
    
    private func handleGenerateSignature(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let dataToSign = arguments["dataToSign"] as? FlutterStandardTypedData,
              let keyIndex = arguments["keyIndex"] as? Int else {
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        usbCardManager.connect { [weak self] success, errorMessage in
            guard let self = self else { return }
            if !success {
                result(FlutterError(code: "COMMUNICATION_ERROR", message: errorMessage ?? "USB connection failed", details: nil))
                return
            }
            
            let aidData = self.dataWithHexString(hex: appletIDHex)
            
            self.usbCardManager.selectApplet(aid: aidData) { success, sw1, sw2, error in
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
                    
                    self.usbCardManager.generateSignature(dataToSign: dataToSign.data, keyIndex: keyIndex) { signatureData, sw1, sw2, error in
                        self.usbCardManager.disconnect()
                        if let signatureData = signatureData {
                            result(FlutterStandardTypedData(bytes: signatureData))
                        } else {
                            result(FlutterError(code: "COMMUNICATION_ERROR", message: "Ký thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                        }
                    }
                }
            }
        }
    }
    
    private func handleGetRsaPublicKey(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let keyRole = arguments["keyRole"] as? String else {
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        usbCardManager.connect { [weak self] success, errorMessage in
            guard let self = self else { return }
            if !success {
                result(FlutterError(code: "COMMUNICATION_ERROR", message: errorMessage ?? "USB connection failed", details: nil))
                return
            }
            
            let aidData = self.dataWithHexString(hex: appletIDHex)
            
            self.usbCardManager.selectApplet(aid: aidData) { success, sw1, sw2, error in
                if !success {
                    self.usbCardManager.disconnect()
                    result(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                    return
                }
                
                self.usbCardManager.getRsaPublicKey(keyRole: keyRole) { keyData, sw1, sw2, error in
                    self.usbCardManager.disconnect()
                    if let keyData = keyData {
                        result(FlutterStandardTypedData(bytes: keyData))
                    } else {
                        result(FlutterError(code: "COMMUNICATION_ERROR", message: "Không thể lấy public key.", details: ["sw1": sw1, "sw2": sw2]))
                    }
                }
            }
        }
    }
    
    private func handleGetCertificate(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let _ = arguments["keyRole"] as? String else {
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        usbCardManager.connect { [weak self] success, errorMessage in
            guard let self = self else { return }
            if !success {
                result(FlutterError(code: "COMMUNICATION_ERROR", message: errorMessage ?? "USB connection failed", details: nil))
                return
            }
            
            let aidData = self.dataWithHexString(hex: appletIDHex)
            
            self.usbCardManager.selectApplet(aid: aidData) { success, sw1, sw2, error in
                if !success {
                    self.usbCardManager.disconnect()
                    result(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                    return
                }
                
                self.usbCardManager.getCertificate(keyRole: "sig") { certData, sw1, sw2, error in
                    self.usbCardManager.disconnect()
                    if let certData = certData {
                        result(FlutterStandardTypedData(bytes: certData))
                    } else {
                        result(FlutterError(code: "COMMUNICATION_ERROR", message: "Không thể lấy certificate.", details: ["sw1": sw1, "sw2": sw2]))
                    }
                }
            }
        }
    }
    
    private func handleDecryptData(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let encryptedData = arguments["encryptedData"] as? FlutterStandardTypedData else {
            result(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            return
        }
        
        usbCardManager.connect { [weak self] success, errorMessage in
            guard let self = self else { return }
            if !success {
                result(FlutterError(code: "COMMUNICATION_ERROR", message: errorMessage ?? "USB connection failed", details: nil))
                return
            }
            
            let aidData = self.dataWithHexString(hex: appletIDHex)
            
            // Step 1: Select Applet
            self.usbCardManager.selectApplet(aid: aidData) { success, sw1, sw2, error in
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
    }
    
    // MARK: - Helpers
    
    private func dataWithHexString(hex: String) -> Data {
        var data = Data()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            let byteString = hex[i..<j]
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            }
            i = j
        }
        return data
    }
}


// MARK: - USB Card Manager for macOS (CryptoTokenKit)

private class MacUsbCardManager {
    
    private var slotManager: TKSmartCardSlotManager?
    private var currentSlot: TKSmartCardSlot?
    private var currentCard: TKSmartCard?
    private var isCompositeDevice = false
    
    private static let tunnelCLA: UInt8 = 0xB0
    private static let tunnelINS: UInt8 = 0xF0
    
    private let logger = MacUsbLogger()
    
    init() {
        self.slotManager = TKSmartCardSlotManager.default
        if self.slotManager == nil {
            logger.debug("⚠️ TKSmartCardSlotManager.default is nil at init time")
            logger.debug("   Possible causes:")
            logger.debug("   1. Missing 'com.apple.security.smartcard' entitlement")
            logger.debug("   2. CryptoTokenKit framework not linked")
            logger.debug("   3. Will retry on first connect() call")
        } else {
            logger.debug("✅ TKSmartCardSlotManager initialized, slots: \(self.slotManager!.slotNames)")
        }
    }
    
    // MARK: - Connection
    
    func isReaderConnected() -> Bool {
        guard let slotManager = slotManager else { return false }
        return !slotManager.slotNames.isEmpty
    }
    
    func connect(completion: @escaping (Bool, String?) -> Void) {
        // Lazy re-initialization: TKSmartCardSlotManager.default may return nil
        // at plugin init time if framework loading is delayed
        if slotManager == nil {
            logger.debug("SlotManager nil, retrying TKSmartCardSlotManager.default...")
            slotManager = TKSmartCardSlotManager.default
        }
        
        guard let slotManager = slotManager else {
            logger.debug("❌ TKSmartCardSlotManager.default is still nil")
            logger.debug("   App sandbox entitlement 'com.apple.security.smartcard' = ???")
            completion(false, "SlotManager không khả dụng. Kiểm tra entitlement 'com.apple.security.smartcard' và chạy lại pod install.")
            return
        }
        
        let slotNames = slotManager.slotNames
        guard let firstSlotName = slotNames.first else {
            completion(false, "Không tìm thấy đầu đọc USB")
            return
        }
        
        logger.debug("Connecting to slot: \(firstSlotName)")
        
        slotManager.getSlot(withName: firstSlotName) { [weak self] slot in
            guard let self = self, let slot = slot else {
                completion(false, "Không thể kết nối với slot: \(firstSlotName)")
                return
            }
            
            self.currentSlot = slot
            self.isCompositeDevice = firstSlotName.contains("AIO")
            
            if self.isCompositeDevice {
                self.logger.debug("Composite device detected — using CCID tunnel")
            }
            
            guard slot.state == .validCard else {
                completion(false, "Không có thẻ trong đầu đọc (state: \(slot.state.rawValue))")
                return
            }
            
            guard let card = slot.makeSmartCard() else {
                completion(false, "Không thể tạo kết nối với thẻ")
                return
            }
            
            self.currentCard = card
            
            card.beginSession { success, error in
                if let error = error {
                    completion(false, "Lỗi phiên làm việc: \(error.localizedDescription)")
                    return
                }
                completion(success, success ? nil : "Không thể bắt đầu phiên làm việc")
            }
        }
    }
    
    func disconnect() {
        currentCard?.endSession()
        currentCard = nil
        currentSlot = nil
    }
    
    // MARK: - APDU Communication
    
    func transmitApdu(_ apdu: Data, completion: @escaping (Data, UInt8, UInt8, Error?) -> Void) {
        guard let card = currentCard else {
            completion(Data(), 0, 0, NSError(domain: "MacUsbCardManager", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Chưa kết nối với thẻ"]))
            return
        }
        
        logger.debug("TX: \(apdu.hexString)")
        
        if isCompositeDevice {
            transmitViaTunnel(card: card, apdu: apdu, completion: completion)
        } else {
            card.transmit(apdu) { [weak self] response, error in
                guard let self = self else { return }
                
                if let error = error {
                    completion(Data(), 0, 0, error)
                    return
                }
                
                guard let response = response, response.count >= 2 else {
                    completion(Data(), 0, 0, NSError(domain: "MacUsbCardManager", code: 2,
                        userInfo: [NSLocalizedDescriptionKey: "Phản hồi quá ngắn"]))
                    return
                }
                
                let sw1 = response[response.count - 2]
                let sw2 = response[response.count - 1]
                let data = response.dropLast(2)
                
                self.logger.debug("RX: SW=\(String(format: "%02X%02X", sw1, sw2)), \(data.count) bytes")
                completion(Data(data), sw1, sw2, nil)
            }
        }
    }
    
    /// Transmit via CCID tunnel for composite devices
    private func transmitViaTunnel(card: TKSmartCard, apdu: Data, completion: @escaping (Data, UInt8, UInt8, Error?) -> Void) {
        var tunnelApdu = Data([MacUsbCardManager.tunnelCLA, MacUsbCardManager.tunnelINS, 0x00, 0x00])
        
        // Encode Lc: use extended length (3-byte) if apdu > 255 bytes (e.g., RSA-4096)
        if apdu.count > 255 {
            tunnelApdu.append(0x00)
            tunnelApdu.append(UInt8((apdu.count >> 8) & 0xFF))
            tunnelApdu.append(UInt8(apdu.count & 0xFF))
        } else {
            tunnelApdu.append(UInt8(apdu.count))
        }
        
        tunnelApdu.append(apdu)
        
        card.transmit(tunnelApdu) { [weak self] response, error in
            guard let self = self else { return }
            
            if let error = error {
                completion(Data(), 0, 0, error)
                return
            }
            
            guard let response = response, response.count >= 2 else {
                completion(Data(), 0, 0, NSError(domain: "MacUsbCardManager", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Tunnel response too short"]))
                return
            }
            
            let tunnelSW1 = response[response.count - 2]
            let tunnelSW2 = response[response.count - 1]
            if tunnelSW1 != 0x90 || tunnelSW2 != 0x00 {
                completion(Data(), 0, 0, NSError(domain: "MacUsbCardManager", code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "Tunnel error"]))
                return
            }
            
            let firstChunk = Data(response.dropLast(2))
            let maxChunkSize = 259
            
            if firstChunk.count < maxChunkSize {
                self.parseTunnelCardResponse(firstChunk, completion: completion)
            } else {
                self.readRemainingChunks(card: card, accumulated: firstChunk, maxChunkSize: maxChunkSize, completion: completion)
            }
        }
    }
    
    private func readRemainingChunks(card: TKSmartCard, accumulated: Data, maxChunkSize: Int, completion: @escaping (Data, UInt8, UInt8, Error?) -> Void) {
        let continueTunnel = Data([MacUsbCardManager.tunnelCLA, MacUsbCardManager.tunnelINS, 0x00, 0x01])
        
        card.transmit(continueTunnel) { [weak self] response, error in
            guard let self = self else { return }
            
            if let error = error {
                completion(Data(), 0, 0, error)
                return
            }
            
            guard let response = response, response.count >= 2 else {
                completion(Data(), 0, 0, NSError(domain: "MacUsbCardManager", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Tunnel continue response too short"]))
                return
            }
            
            let tunnelSW1 = response[response.count - 2]
            let tunnelSW2 = response[response.count - 1]
            if tunnelSW1 != 0x90 || tunnelSW2 != 0x00 {
                completion(Data(), 0, 0, NSError(domain: "MacUsbCardManager", code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "Tunnel continue error"]))
                return
            }
            
            let chunk = Data(response.dropLast(2))
            var total = accumulated
            total.append(chunk)
            
            if chunk.count < maxChunkSize {
                self.parseTunnelCardResponse(total, completion: completion)
            } else {
                self.readRemainingChunks(card: card, accumulated: total, maxChunkSize: maxChunkSize, completion: completion)
            }
        }
    }
    
    private func parseTunnelCardResponse(_ cardResponse: Data, completion: @escaping (Data, UInt8, UInt8, Error?) -> Void) {
        guard cardResponse.count >= 2 else {
            completion(Data(), 0, 0, NSError(domain: "MacUsbCardManager", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Card response quá ngắn"]))
            return
        }
        
        let sw1 = cardResponse[cardResponse.count - 2]
        let sw2 = cardResponse[cardResponse.count - 1]
        let data = cardResponse.dropLast(2)
        
        logger.debug("RX: SW=\(String(format: "%02X%02X", sw1, sw2)), \(data.count) bytes")
        completion(Data(data), sw1, sw2, nil)
    }
    
    func transmitApduWithGetResponse(_ apdu: Data, completion: @escaping (Data, UInt8, UInt8, Error?) -> Void) {
        var accumulatedData = Data()
        
        func recursiveTransmit(_ command: Data) {
            transmitApdu(command) { [weak self] responseData, sw1, sw2, error in
                guard let _ = self else { return }
                
                if let error = error {
                    completion(Data(), sw1, sw2, error)
                    return
                }
                
                accumulatedData.append(responseData)
                
                if sw1 == 0x61 {
                    let getResponseApdu = Data([0x00, 0xC0, 0x00, 0x00, sw2])
                    recursiveTransmit(getResponseApdu)
                } else {
                    completion(accumulatedData, sw1, sw2, nil)
                }
            }
        }
        
        recursiveTransmit(apdu)
    }
    
    // MARK: - High-Level Card Operations
    
    func selectApplet(aid: Data, completion: @escaping (Bool, UInt8, UInt8, Error?) -> Void) {
        var apdu = Data([0x00, 0xA4, 0x04, 0x00, UInt8(aid.count)])
        apdu.append(aid)
        
        transmitApduWithGetResponse(apdu) { _, sw1, sw2, error in
            completion(error == nil && sw1 == 0x90 && sw2 == 0x00, sw1, sw2, error)
        }
    }
    
    func verifyPin(pin: String, completion: @escaping (Bool, UInt8, UInt8, Error?) -> Void) {
        let pinData = Data(pin.utf8)
        var apdu = Data([0x00, 0x20, 0x00, 0x81, UInt8(pinData.count)])
        apdu.append(pinData)
        
        transmitApduWithGetResponse(apdu) { _, sw1, sw2, error in
            completion(error == nil && sw1 == 0x90 && sw2 == 0x00, sw1, sw2, error)
        }
    }
    
    func verifyPinForDecrypt(pin: String, completion: @escaping (Bool, UInt8, UInt8, Error?) -> Void) {
        let pinData = Data(pin.utf8)
        var apdu = Data([0x00, 0x20, 0x00, 0x82, UInt8(pinData.count)])
        apdu.append(pinData)
        
        transmitApduWithGetResponse(apdu) { _, sw1, sw2, error in
            completion(error == nil && sw1 == 0x90 && sw2 == 0x00, sw1, sw2, error)
        }
    }
    
    func generateSignature(dataToSign: Data, keyIndex: Int, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        let p2: UInt8
        switch keyIndex {
        case 1: p2 = 0x9B
        case 2: p2 = 0x9C
        default: p2 = 0x9A
        }
        
        var apdu = Data([0x00, 0x2A, 0x9E, p2, UInt8(dataToSign.count)])
        apdu.append(dataToSign)
        apdu.append(0x00)
        
        transmitApduWithGetResponse(apdu) { responseData, sw1, sw2, error in
            if error == nil && sw1 == 0x90 && sw2 == 0x00 {
                completion(responseData, sw1, sw2, nil)
            } else {
                completion(nil, sw1, sw2, error)
            }
        }
    }
    
    func getRsaPublicKey(keyRole: String, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        let roleData: Data
        switch keyRole {
        case "sig": roleData = Data([0xB6, 0x00])
        case "dec": roleData = Data([0xB8, 0x00])
        case "aut": roleData = Data([0xA4, 0x00])
        case "sm":  roleData = Data([0xA6, 0x00])
        default:
            completion(nil, 0, 0, NSError(domain: "MacUsbCardManager", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Vai trò khóa không hợp lệ: \(keyRole)"]))
            return
        }
        
        var apdu = Data([0x00, 0x47, 0x81, 0x00, UInt8(roleData.count)])
        apdu.append(roleData)
        apdu.append(0x00)
        
        transmitApduWithGetResponse(apdu) { responseData, sw1, sw2, error in
            if error == nil && sw1 == 0x90 && sw2 == 0x00 {
                completion(responseData, sw1, sw2, nil)
            } else {
                completion(nil, sw1, sw2, error)
            }
        }
    }
    
    func getCertificate(keyRole: String, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        let selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
        var selectApdu = Data([0x00, 0xA5, 0x02, 0x04, UInt8(selectCertData.count)])
        selectApdu.append(selectCertData)
        selectApdu.append(0x00)
        
        transmitApduWithGetResponse(selectApdu) { [weak self] _, sw1, sw2, error in
            guard let self = self else { return }
            
            if error != nil || sw1 != 0x90 || sw2 != 0x00 {
                completion(nil, sw1, sw2, error)
                return
            }
            
            let getCertApdu = Data([0x00, 0xCA, 0x7F, 0x21, 0x00, 0x08, 0x00])
            
            self.transmitApduWithGetResponse(getCertApdu) { responseData, sw1, sw2, error in
                if error == nil && sw1 == 0x90 && sw2 == 0x00 {
                    completion(responseData, sw1, sw2, nil)
                } else {
                    completion(nil, sw1, sw2, error)
                }
            }
        }
    }
    
    func decryptData(encryptedData: Data, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        var fullData = Data([0x00])
        fullData.append(encryptedData)
        
        logger.debug("PSO:DECIPHER total data: \(fullData.count) bytes, composite=\(isCompositeDevice)")
        
        let maxChunkSize = 255
        var chunks: [Data] = []
        var offset = 0
        while offset < fullData.count {
            let end = min(offset + maxChunkSize, fullData.count)
            chunks.append(fullData[offset..<end])
            offset = end
        }
        
        logger.debug("PSO:DECIPHER split into \(chunks.count) chunks")
        
        if isCompositeDevice {
            sendChainedDecipherDirect(chunks: chunks, chunkIndex: 0, completion: completion)
        } else {
            sendChainedDecipher(chunks: chunks, chunkIndex: 0, completion: completion)
        }
    }
    
    /// Send chained PSO:DECIPHER directly to TKSmartCard (bypassing CCID tunnel)
    private func sendChainedDecipherDirect(chunks: [Data], chunkIndex: Int, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        guard let card = currentCard, chunkIndex < chunks.count else {
            completion(nil, 0, 0, NSError(domain: "MacUsbCardManager", code: 5,
                userInfo: [NSLocalizedDescriptionKey: "No card or chunks"]))
            return
        }
        
        let chunk = chunks[chunkIndex]
        let isLast = (chunkIndex == chunks.count - 1)
        let cla: UInt8 = isLast ? 0x00 : 0x10
        
        var apdu = Data([cla, 0x2A, 0x80, 0x86, UInt8(chunk.count)])
        apdu.append(chunk)
        if isLast { apdu.append(0x00) }
        
        logger.debug("PSO:DECIPHER direct chunk \(chunkIndex+1)/\(chunks.count): CLA=\(String(format: "%02X", cla)), \(chunk.count) bytes")
        
        card.transmit(apdu) { [weak self] response, error in
            guard let self = self else { return }
            
            if let error = error {
                self.logger.debug("Direct transmit error: \(error.localizedDescription)")
                completion(nil, 0, 0, error)
                return
            }
            
            guard let response = response, response.count >= 2 else {
                completion(nil, 0, 0, NSError(domain: "MacUsbCardManager", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Response too short"]))
                return
            }
            
            let sw1 = response[response.count - 2]
            let sw2 = response[response.count - 1]
            let data = Data(response.dropLast(2))
            
            self.logger.debug("PSO:DECIPHER direct RX: SW=\(String(format: "%02X%02X", sw1, sw2)), data=\(data.count) bytes")
            
            if !isLast {
                if sw1 == 0x90 && sw2 == 0x00 {
                    self.sendChainedDecipherDirect(chunks: chunks, chunkIndex: chunkIndex + 1, completion: completion)
                } else {
                    completion(nil, sw1, sw2, NSError(domain: "MacUsbCardManager", code: 6,
                        userInfo: [NSLocalizedDescriptionKey: "Command chaining failed at chunk \(chunkIndex+1)"]))
                }
            } else {
                if sw1 == 0x90 && sw2 == 0x00 {
                    completion(data, sw1, sw2, nil)
                } else if sw1 == 0x61 {
                    self.accumulateGetResponse(card: card, accumulated: data, remaining: Int(sw2), completion: completion)
                } else {
                    completion(nil, sw1, sw2, nil)
                }
            }
        }
    }
    
    /// Accumulate GET RESPONSE data for direct transmit mode
    private func accumulateGetResponse(card: TKSmartCard, accumulated: Data, remaining: Int, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        let le: UInt8 = remaining > 0 ? UInt8(min(remaining, 256) & 0xFF) : 0x00
        let getResp = Data([0x00, 0xC0, 0x00, 0x00, le])
        
        card.transmit(getResp) { [weak self] response, error in
            guard let self = self else { return }
            
            if let error = error {
                completion(nil, 0, 0, error)
                return
            }
            
            guard let response = response, response.count >= 2 else {
                completion(nil, 0, 0, NSError(domain: "MacUsbCardManager", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "GET RESPONSE too short"]))
                return
            }
            
            let sw1 = response[response.count - 2]
            let sw2 = response[response.count - 1]
            let data = Data(response.dropLast(2))
            var total = accumulated
            total.append(data)
            
            self.logger.debug("GET RESPONSE: \(data.count) bytes, SW=\(String(format: "%02X%02X", sw1, sw2)), total=\(total.count)")
            
            if sw1 == 0x61 {
                self.accumulateGetResponse(card: card, accumulated: total, remaining: Int(sw2), completion: completion)
            } else {
                completion(total, sw1, sw2, nil)
            }
        }
    }
    
    private func sendChainedDecipher(chunks: [Data], chunkIndex: Int, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        guard chunkIndex < chunks.count else {
            completion(nil, 0, 0, NSError(domain: "MacUsbCardManager", code: 5,
                userInfo: [NSLocalizedDescriptionKey: "No chunks to send"]))
            return
        }
        
        let chunk = chunks[chunkIndex]
        let isLast = (chunkIndex == chunks.count - 1)
        let cla: UInt8 = isLast ? 0x00 : 0x10
        
        var apdu = Data([cla, 0x2A, 0x80, 0x86, UInt8(chunk.count)])
        apdu.append(chunk)
        if isLast {
            apdu.append(0x00)
        }
        
        logger.debug("PSO:DECIPHER chunk \(chunkIndex+1)/\(chunks.count): CLA=\(String(format: "%02X", cla)), \(chunk.count) bytes")
        
        if isLast {
            transmitApduWithGetResponse(apdu) { responseData, sw1, sw2, error in
                if error == nil && sw1 == 0x90 && sw2 == 0x00 {
                    completion(responseData, sw1, sw2, nil)
                } else {
                    completion(nil, sw1, sw2, error)
                }
            }
        } else {
            transmitApdu(apdu) { [weak self] _, sw1, sw2, error in
                guard let self = self else { return }
                
                if error != nil || sw1 != 0x90 || sw2 != 0x00 {
                    completion(nil, sw1, sw2, error ?? NSError(domain: "MacUsbCardManager", code: 6,
                        userInfo: [NSLocalizedDescriptionKey: "Command chaining failed at chunk \(chunkIndex+1)"]))
                    return
                }
                
                self.sendChainedDecipher(chunks: chunks, chunkIndex: chunkIndex + 1, completion: completion)
            }
        }
    }
}

// MARK: - Extensions

private extension Data {
    var hexString: String {
        return map { String(format: "%02X", $0) }.joined(separator: " ")
    }
}

private class MacUsbLogger {
    func debug(_ message: String) {
        #if DEBUG
        print("🔌 [macOS-USB] \(message)")
        #endif
    }
}
