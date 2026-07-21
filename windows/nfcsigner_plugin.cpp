#define NOMINMAX  // Ngăn chặn định nghĩa min và max từ windows.h

#include "nfcsigner_plugin.h"

#include <windows.h>
// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <winscard.h>
#include <memory>
#include <sstream>
#include <iostream>
#include <string>

#ifdef HAVE_PODOFO
// Include PoDoFo và OpenSSL
#include <podofo/podofo.h>
//#include <podofo/private/PdfDeclarationsPrivate.h>
//#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
//#include <podofo/private/OpenSSLInternal.h>
using namespace PoDoFo;
#endif

namespace nfcsigner {

    // Helper function to convert hex string to byte vector
    std::vector<uint8_t> HexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        if (hex.length() % 2 != 0) {
            throw std::runtime_error("Hex string must have even length");
        }

        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            char* end;
            uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), &end, 16));
            if (*end != '\0') {
                throw std::runtime_error("Invalid hex character");
            }
            bytes.push_back(byte);
        }
        return bytes;
    }
    template<typename T>
    std::string ToHexString(const T& data) {
        const char hex_chars[] = "0123456789abcdef";
        std::string hex_str;
        hex_str.reserve(data.size() * 2); // Cấp phát sẵn bộ nhớ để tăng hiệu quả

        for (unsigned char byte : data) {
            hex_str += hex_chars[(byte >> 4) & 0x0F]; // Ký tự cho 4 bit cao
            hex_str += hex_chars[byte & 0x0F];        // Ký tự cho 4 bit thấp
        }

        return hex_str;
    }
    std::vector<uint8_t> CreateSelectAppletCommand(const std::string& appletID) {
        auto appletID_bytes = HexToBytes(appletID);
        std::vector<uint8_t> cmd = { 0x00, 0xA4, 0x04, 0x00, (uint8_t)appletID_bytes.size() };
        cmd.insert(cmd.end(), appletID_bytes.begin(), appletID_bytes.end());
        cmd.push_back(0x00);
        return cmd;
    }

    std::vector<uint8_t> CreateVerifyPinCommand(const std::string& pin) {
        std::vector<uint8_t> pin_bytes(pin.begin(), pin.end());
        std::vector<uint8_t> cmd = { 0x00, 0x20, 0x00, 0x81, (uint8_t)pin_bytes.size() };
        cmd.insert(cmd.end(), pin_bytes.begin(), pin_bytes.end());
        return cmd;
    }

    std::vector<uint8_t> CreateComputeSignatureCommand(const std::vector<uint8_t>& data, int keyIndex) {
        uint8_t p1 = 0x9E;
        uint8_t p2;
        switch (keyIndex) {
            case 1: p2 = 0x9B; break;
            case 2: p2 = 0x9C; break;
            default: p2 = 0x9A; break;
        }
        std::vector<uint8_t> cmd = { 0x00, 0x2A, p1, p2, (uint8_t)data.size() };
        cmd.insert(cmd.end(), data.begin(), data.end());
        cmd.push_back(0x00);
        return cmd;
    }

    std::vector<uint8_t> CreateSelectCertificateCommand() {
        std::vector<uint8_t> data = { 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21 };
        std::vector<uint8_t> cmd = { 0x00, 0xA5, 0x02, 0x04, (uint8_t)data.size() };
        cmd.insert(cmd.end(), data.begin(), data.end());
        cmd.push_back(0x00);
        return cmd;
    }
    std::vector<uint8_t> CreateGetRsaPublicKeyCommand(const std::string& keyRole) {
        std::vector<uint8_t> data;
        if (keyRole == "sig") data = { 0xB6, 0x00 };
        else if (keyRole == "dec") data = { 0xB8, 0x00 };
        else if (keyRole == "aut") data = { 0xA4, 0x00 };
        else if (keyRole == "sm") data = { 0xA6, 0x00 };
        else throw std::runtime_error("Invalid key role.");

        std::vector<uint8_t> cmd = { 0x00, 0x47, 0x81, 0x00, (uint8_t)data.size() };
        cmd.insert(cmd.end(), data.begin(), data.end());
        cmd.push_back(0x00);
        return cmd;
    }
    std::vector<uint8_t> CreateGetCertificateCommand() {
        return { 0x00, 0xCA, 0x7F, 0x21, 0x00 };
    }

// static
void NfcsignerPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "nfcsigner",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<NfcsignerPlugin>();

  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto &call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

NfcsignerPlugin::NfcsignerPlugin() {}

NfcsignerPlugin::~NfcsignerPlugin() {}

void NfcsignerPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
    const auto* args = std::get_if<flutter::EncodableMap>(method_call.arguments());

    if (method_call.method_name().compare("generateSignature") == 0) {
        HandleSign(args, std::move(result));
    } else if (method_call.method_name().compare("getRsaPublicKey") == 0) {
        HandleGetPublicKey(args, std::move(result));
    } else if (method_call.method_name().compare("getCertificate") == 0) {
        HandleGetCertificate(args, std::move(result));
    } else if (method_call.method_name().compare("signPdf") == 0) {
        HandleSignPdf(args, std::move(result));
    } else if (method_call.method_name().compare("decryptData") == 0) {
        HandleDecryptData(args, std::move(result));
    } else if (method_call.method_name().compare("getPlatformVersion") == 0) {
        std::ostringstream version_stream;
        version_stream << "Windows ";
        if (IsWindows10OrGreater()) version_stream << "10+";
        else if (IsWindows8OrGreater()) version_stream << "8";
        else version_stream << "(unknown)";
        result->Success(flutter::EncodableValue(version_stream.str()));
    } else {
    result->NotImplemented();
  }
}
// Wrapper for an entire card operation
    template<typename Func>
    void CardOperation(Func&& operation, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        SCARDCONTEXT hContext = 0;
        SCARDHANDLE hCard = 0;
        DWORD dwActiveProtocol = 0;

        try {
            LONG lReturn = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
            if (lReturn != SCARD_S_SUCCESS) throw std::runtime_error("SCardEstablishContext failed.");

            DWORD dwReaders = SCARD_AUTOALLOCATE;
            LPTSTR mszReaders = NULL;
            lReturn = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
            if (lReturn != SCARD_S_SUCCESS || mszReaders == NULL || mszReaders[0] == '\0') {
                if (mszReaders) SCardFreeMemory(hContext, mszReaders);
                throw std::runtime_error("No card reader found.");
            }

            lReturn = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
            SCardFreeMemory(hContext, mszReaders);
            if (lReturn != SCARD_S_SUCCESS) throw std::runtime_error("SCardConnect failed. Is a card inserted?");

            std::cout << "[CardOperation] Connected with protocol: " << (dwActiveProtocol == SCARD_PROTOCOL_T0 ? "T0" : "T1") << std::endl;
            operation(hCard, dwActiveProtocol);

        } catch (const std::runtime_error& e) {
            result->Error("PC/SC_ERROR", e.what());
        }

        if (hCard) SCardDisconnect(hCard, SCARD_LEAVE_CARD);
        if (hContext) SCardReleaseContext(hContext);
    }

// APDU Transmit function with GET RESPONSE handling
    std::vector<uint8_t> NfcsignerPlugin::TransmitAndGetResponse(SCARDHANDLE hCard, const std::vector<uint8_t>& command, DWORD dwActiveProtocol) {

        const SCARD_IO_REQUEST* pci = (dwActiveProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;

        const DWORD BUFFER_SIZE = 4096;
        std::vector<uint8_t> response_buffer(BUFFER_SIZE, 0);
        DWORD response_len = BUFFER_SIZE;

        LONG lReturn = SCardTransmit(hCard, pci, command.data(), (DWORD)command.size(), NULL, response_buffer.data(), &response_len);
        if (lReturn != SCARD_S_SUCCESS) {
            std::ostringstream oss;
            oss << "SCardTransmit failed (0x" << std::hex << lReturn << ")";
            throw std::runtime_error(oss.str());
        }
        response_buffer.resize(response_len);

        if (response_len >= 2 && response_buffer[response_len - 2] == 0x61) {
            std::vector<uint8_t> full_response_data;
            if (response_len > 2) {
                full_response_data.insert(full_response_data.end(), response_buffer.begin(), response_buffer.end() - 2);
            }

            while (response_buffer[response_len - 2] == 0x61) {
                uint8_t le = response_buffer[response_len - 1];
                std::vector<uint8_t> get_response_cmd = { 0x00, 0xC0, 0x00, 0x00, le };

                response_len = BUFFER_SIZE;
                response_buffer.assign(BUFFER_SIZE, 0);

                lReturn = SCardTransmit(hCard, pci, get_response_cmd.data(), (DWORD)get_response_cmd.size(), NULL, response_buffer.data(), &response_len);
                if (lReturn != SCARD_S_SUCCESS) {
                    throw std::runtime_error("SCardTransmit failed during GET RESPONSE.");
                }
                response_buffer.resize(response_len);

                if (response_len > 2) {
                    full_response_data.insert(full_response_data.end(), response_buffer.begin(), response_buffer.end() - 2);
                }
            }
            full_response_data.push_back(response_buffer[response_len - 2]);
            full_response_data.push_back(response_buffer[response_len - 1]);
            return full_response_data;
        }

        return response_buffer;
    }
    void NfcsignerPlugin::HandleSign(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
            // Lấy tham số
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
            auto pin = std::get<std::string>(args->at(flutter::EncodableValue("pin")));
            auto dataToSign = std::get<std::vector<uint8_t>>(args->at(flutter::EncodableValue("dataToSign")));
            auto keyIndex = std::get<int>(args->at(flutter::EncodableValue("keyIndex")));

            // Chuỗi lệnh APDU
            auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
            if (select_resp.back() != 0x00 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn Applet thất bại.");
            }

            auto verify_resp = TransmitAndGetResponse(hCard, CreateVerifyPinCommand(pin), dwActiveProtocol);
            if (verify_resp.back() != 0x00 || verify_resp[verify_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Xác thực PIN thất bại.");
            }

            auto sign_resp = TransmitAndGetResponse(hCard, CreateComputeSignatureCommand(dataToSign, keyIndex), dwActiveProtocol);
            if (sign_resp.back() != 0x00 || sign_resp[sign_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Ký số thất bại.");
            }

            std::vector<uint8_t> signature_data(sign_resp.begin(), sign_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(signature_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
    // Handler for getRsaPublicKey
    void NfcsignerPlugin::HandleGetPublicKey(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
            // Extract args
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
            auto keyRole = std::get<std::string>(args->at(flutter::EncodableValue("keyRole")));

            // APDU command definitions
            auto select_cmd = CreateSelectAppletCommand(appletID);
            auto get_key_cmd = CreateGetRsaPublicKeyCommand(keyRole);

            // Transmit sequence
            auto select_resp = TransmitAndGetResponse(hCard, select_cmd, dwActiveProtocol);
            if (select_resp.size() < 2 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Select Applet failed.");
            }

            auto key_resp = TransmitAndGetResponse(hCard, get_key_cmd, dwActiveProtocol);
            if (key_resp.size() < 2 || key_resp[key_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Get Public Key failed.");
            }

            // Return success
            std::vector<uint8_t> key_data(key_resp.begin(), key_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(key_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
    void NfcsignerPlugin::HandleGetCertificate(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
            // Lấy tham số
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));

            // Chuỗi lệnh APDU
            auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
            if (select_resp.back() != 0x00 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn Applet thất bại.");
            }

            auto select_cert_resp = TransmitAndGetResponse(hCard, CreateSelectCertificateCommand(), dwActiveProtocol);
            if (select_cert_resp.back() != 0x00 || select_cert_resp[select_cert_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn dữ liệu Certificate thất bại.");
            }

            auto cert_resp = TransmitAndGetResponse(hCard, CreateGetCertificateCommand(), dwActiveProtocol);
            if (cert_resp.back() != 0x00 || cert_resp[cert_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Lấy Certificate thất bại.");
            }

            std::vector<uint8_t> cert_data(cert_resp.begin(), cert_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(cert_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
    void NfcsignerPlugin::HandleSignPdf(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {

        auto p_result = result.release();

        CardOperation([this, args, p_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
            try {
                // 1. Lấy tất cả tham số từ Flutter
                std::cout << "=== Starting PDF Signing Process ===" << std::endl;
                std::cout << "PoDoFo version: " << PODOFO_VERSION_STRING << std::endl;
                // 1. Lấy và validate các tham số
                if (!args) {
                    throw std::runtime_error("Arguments are null");
                }
                std::cout << "=== Starting get Parameters ===" << std::endl;
                auto pdfBytes = std::get<std::vector<uint8_t>>(args->at(flutter::EncodableValue("pdfBytes")));
                auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
                auto pin = std::get<std::string>(args->at(flutter::EncodableValue("pin")));
                auto keyIndex = std::get<int>(args->at(flutter::EncodableValue("keyIndex")));
                auto reason = std::get<std::string>(args->at(flutter::EncodableValue("reason")));
                auto location = std::get<std::string>(args->at(flutter::EncodableValue("location")));
                // signatureLength may not be sent from Dart; default to 512 (RSA 4096)
                int signatureLength = 512;
                auto sigLen_iter = args->find(flutter::EncodableValue("signatureLength"));
                if (sigLen_iter != args->end()) {
                    signatureLength = std::get<int>(sigLen_iter->second);
                }

                // Lấy DigestInfo bạn đã cung cấp
                auto data_to_send_to_card = std::get<std::vector<uint8_t>>(args->at(flutter::EncodableValue("pdfHashBytes")));
                if (data_to_send_to_card.empty()) {
                    throw std::runtime_error("pdfHashBytes cannot be empty.");
                }
                double x = 50.0, y = 700.0, width = 200.0, height = 50.0;
                int pageNumber = 1;
                std::string contact = "info@bmctech.vn";
                std::string signerName = "BMC T&S JSC";

                auto config_iter = args->find(flutter::EncodableValue("signatureConfig"));
                std::vector<uint8_t> signatureImageBytes;
                double signatureImageWidth = 50.0, signatureImageHeight = 50.0;
                std::string signDate;
                if (config_iter != args->end()) {
                    auto signatureConfig = std::get<flutter::EncodableMap>(config_iter->second);

                    auto x_iter = signatureConfig.find(flutter::EncodableValue("x"));
                    auto y_iter = signatureConfig.find(flutter::EncodableValue("y"));
                    auto width_iter = signatureConfig.find(flutter::EncodableValue("width"));
                    auto height_iter = signatureConfig.find(flutter::EncodableValue("height"));
                    auto page_iter = signatureConfig.find(flutter::EncodableValue("pageNumber"));
                    auto contact_iter = signatureConfig.find(flutter::EncodableValue("contact"));
                    auto signerName_iter = signatureConfig.find(flutter::EncodableValue("signerName"));
                    auto signatureImage_iter = signatureConfig.find(flutter::EncodableValue("signatureImage"));
                    auto signatureImageWidth_iter = signatureConfig.find(flutter::EncodableValue("signatureImageWidth"));
                    auto signatureImageHeight_iter = signatureConfig.find(flutter::EncodableValue("signatureImageHeight"));
                    auto signDate_iter = signatureConfig.find(flutter::EncodableValue("signDate"));

                    if (x_iter != signatureConfig.end()) x = std::get<double>(x_iter->second);
                    if (y_iter != signatureConfig.end()) y = std::get<double>(y_iter->second);
                    if (width_iter != signatureConfig.end()) width = std::get<double>(width_iter->second);
                    if (height_iter != signatureConfig.end()) height = std::get<double>(height_iter->second);
                    if (page_iter != signatureConfig.end()) pageNumber = std::get<int>(page_iter->second);
                    if (contact_iter != signatureConfig.end()) contact = std::get<std::string>(contact_iter->second);
                    if (signerName_iter != signatureConfig.end()) signerName = std::get<std::string>(signerName_iter->second);
                    if (signatureImage_iter != signatureConfig.end()) signatureImageBytes = std::get<std::vector<uint8_t>>(signatureImage_iter->second);
                    if(signatureImageWidth_iter != signatureConfig.end()) signatureImageWidth = std::get<double>(signatureImageWidth_iter->second);
                    if(signatureImageHeight_iter != signatureConfig.end()) signatureImageHeight = std::get<double>(signatureImageHeight_iter->second);
                    if (signDate_iter != signatureConfig.end()) signDate = std::get<std::string>(signDate_iter->second);
                }

                // 2. Giao tiếp với thẻ để lấy Certificate
                // Việc ký sẽ được thực hiện sau bên trong callback của PoDoFo
                std::cout << "Selecting applet..." << std::endl;
                auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
                if (select_resp.size() < 2 || select_resp[select_resp.size() - 2] != 0x90) throw std::runtime_error("Select Applet failed.");

                std::cout << "Verifying PIN..." << std::endl;
                auto verify_resp = TransmitAndGetResponse(hCard, CreateVerifyPinCommand(pin), dwActiveProtocol);
                if (verify_resp.size() < 2 || verify_resp[verify_resp.size() - 2] != 0x90) throw std::runtime_error("Verify PIN failed.");

                std::cout << "Selecting certificate..." << std::endl;
                auto select_cert_resp = TransmitAndGetResponse(hCard, CreateSelectCertificateCommand(), dwActiveProtocol);
                if (select_cert_resp.size() < 2 || select_cert_resp[select_cert_resp.size() - 2] != 0x90) throw std::runtime_error("Select Certificate data object failed.");

                auto cert_resp = TransmitAndGetResponse(hCard, CreateGetCertificateCommand(), dwActiveProtocol);
                if (cert_resp.size() < 2 || cert_resp[cert_resp.size() - 2] != 0x90) throw std::runtime_error("Get Certificate failed.");
                std::vector<uint8_t> certificate_data(cert_resp.begin(), cert_resp.end() - 2);
                if (certificate_data.empty()) throw std::runtime_error("Certificate from card is empty.");

                // 3. Chuẩn bị tài liệu PDF và trường chữ ký bằng PoDoFo API mới
                std::cout << "Loading PDF document..." << std::endl;

                // Code load PDF hiện tại
                PoDoFo::PdfMemDocument document;
                document.LoadFromBuffer(PoDoFo::bufferview(
                        reinterpret_cast<const char*>(pdfBytes.data()), pdfBytes.size()
                ));
                std::cout << "PDF loaded successfully. Page count: " << document.GetPages().GetCount() << std::endl;

                PoDoFo::PdfPage& page = document.GetPages().GetPageAt(pageNumber > 0 ? pageNumber - 1 : 0);

                // API mới để tạo field chữ ký
                std::cout << "=== API for Signature ===" << std::endl;
                Rect annot_rect = PoDoFo::Rect(x, y, width, height);
                auto& signatureField = page.CreateField<PoDoFo::PdfSignature>(
                        "BMC-Signature", annot_rect
                );
                std::cout << "=== Starting set some signature parameters===" << std::endl;
                PdfDate  dateString = PoDoFo::PdfDate::LocalNow();
                signatureField.SetSignatureReason(PoDoFo::PdfString(reason));
                signatureField.SetSignatureLocation(PoDoFo::PdfString(location));
                signatureField.SetSignerName(PoDoFo::PdfString(signerName));
                signatureField.SetSignatureDate(dateString);

                auto sigXObject = document.CreateXObjectForm(annot_rect);

                if (sigXObject) {
                    PoDoFo::PdfPainter painter;
                    // API CHUẨN 3: SetCanvas hoạt động với đối tượng trả về từ CreateXObjectForm
                    painter.SetCanvas(*sigXObject);
                    // Tạo một đối tượng màu (ở đây là màu đen)
                    PoDoFo::PdfColor black(0.0, 0.0, 0.0);
                    painter.GraphicsState.SetStrokingColor(black);
                    painter.GraphicsState.SetNonStrokingColor(black);
                    const double sig_width = annot_rect.Width;
                    const double sig_height = annot_rect.Height;
                    //std::cout << "=== Signature width: " << sig_width <<" Signature height: " << sig_height << " ===" << std::endl;
                    // Vẽ đường viền
                    painter.DrawRectangle(0, 0, sig_width, sig_height);

                    //auto* fontBold = document.GetFonts().SearchFont("Helvetica-Bold");
                    auto* fontRegular = document.GetFonts().SearchFont("Helvetica");

                    std::string line1 = "Người ký: " + signerName;
                    std::string line2 = "Email: " + contact;
                    std::string line3 = "Ngày ký: " + signDate;
                    Rect tex_rect = PoDoFo::Rect( x+ 80, y - 5, width - 80, height);
                    if (fontRegular) {
                        painter.TextState.SetFont(*fontRegular, 11);
                        painter.DrawTextMultiLine(
                                            line1 +  "\n" +
                                            line2 + "\n" +
                                            line3,
                                            tex_rect
                                            );
                    }

                    if (!signatureImageBytes.empty()) {
                        //std::cout << "=== Đang lấy thông tin signatureImageBytes ===" << std::endl;
                        try {
                            auto image = document.CreateImage();
                            image->LoadFromBuffer(
                                    PoDoFo::bufferview(
                                            reinterpret_cast<const char*>(signatureImageBytes.data()),
                                            signatureImageBytes.size()
                                    )
                            );
                            //std::cout << "=== signatureImageBytes Height:" << image->GetHeight() << " Width: " << image->GetWidth()  << std::endl;
                            if (image->GetWidth() > 0 && image->GetHeight() > 0) {
                                double img_h = signatureImageHeight; // Chiều cao mong muốn của ảnh
                                double img_w = signatureImageWidth; // Chiều rộng mong muốn của ảnh
                                double scale_y = img_h / image->GetHeight();
                                double scale_x = img_w / image->GetWidth();

                                painter.DrawImage(*image, x + 2, y + (annot_rect.Height - img_h)/2, scale_x, scale_y);
                            }
                        } catch(const PoDoFo::PdfError& e) {
                            std::cerr << "Warning: Không thể load ảnh chữ ký: " << e.what() << std::endl;
                        }
                    }
                    //painter.Save();
                    painter.FinishDrawing();

                    signatureField.MustGetWidget().SetAppearanceStream(*sigXObject);
                }
                // =====================================================================================================
                std::cout << "=== Successfully set signature reason/location ===" << std::endl;
                // 4. Cấu hình PdfSignerCms với callback để ký bằng thẻ
                std::cout << "=== Cấu hình PdfSignerCms với callback để ký bằng thẻ ===" << std::endl;
                PoDoFo::PdfSignerCmsParams params;
                //params.SignatureType = PoDoFo::PdfSignatureType::Adobe.PPKLite;
                //params.Encryption = PoDoFo::PdfSignatureEncryption::RSA;
                params.Hashing = PoDoFo::PdfHashingAlgorithm::SHA256;
                params.Flags = PoDoFo::PdfSignerCmsFlags::ServiceDoDryRun;

                params.SigningService = [&](PoDoFo::bufferview hashToSign, bool dryrun, PoDoFo::charbuff& signedHash) {
                    // Thêm log để biết chúng ta đang ở bước nào
                    std::cout << "--> Entering SigningService. Is dry run: " << (dryrun ? "YES" : "NO") << std::endl;

                    const size_t signatureSize = static_cast<size_t>(signatureLength);

                    if (dryrun) {
                        // Lần 1: Báo cho PoDoFo kích thước cần thiết. Thao tác resize ở đây là ĐÚNG.
                        std::cout << "Dry run: Informing PoDoFo that signature will be " << signatureSize << " bytes." << std::endl;
                        signedHash.resize(signatureSize);
                        std::cout << "<-- Exiting SigningService (Dry run complete)." << std::endl;
                        return;
                    }

                    std::cout << "Real run: Getting signature from card..." << std::endl;
                    auto sign_resp = TransmitAndGetResponse(hCard, CreateComputeSignatureCommand(data_to_send_to_card, keyIndex), dwActiveProtocol);
                    if (sign_resp.size() < 2 || sign_resp[sign_resp.size() - 2] != 0x90) {
                        throw std::runtime_error("Compute signature failed on card inside callback.");
                    }

                    std::vector<uint8_t> signature_raw(sign_resp.begin(), sign_resp.end() - 2);

                    std::cout << "Real run: PoDoFo provided a buffer of size " << signedHash.size() << " bytes." << std::endl;
                    // Kiểm tra an toàn: đảm bảo bộ đệm PoDoFo cấp phát đủ lớn.
                    if (signedHash.size() < signature_raw.size()) {
                        throw std::runtime_error("PoDoFo allocated a buffer that is too small for the actual signature.");
                    }

                    std::cout << "Real run: Copying " << signature_raw.size() << " signature bytes into the buffer." << std::endl;
                    if (!signature_raw.empty()) {
                        //signedHash.resize(signature_raw.size());
                        signedHash.assign(signature_raw.begin(), signature_raw.end());
                        //memcpy(signedHash.data(), signature_raw.data(), signature_raw.size());
                    }
                    std::cout << "<-- Exiting SigningService (Real run complete)." << std::endl;
                };
                // Tạo đối tượng signer
                PoDoFo::PdfSignerCms signer(
                        PoDoFo::bufferview(reinterpret_cast<const char*>(certificate_data.data()), certificate_data.size()),
                        params
                );

                std::cout << "=== Tạo đối tượng signer Successfully ===" << std::endl;
                // 5. Thực hiện ký - SỬ DỤNG PoDoFo::VectorStreamDevice có sẵn
                std::cout << "=== 5. Thực hiện ký - SỬ DỤNG PoDoFo::VectorStreamDevice có sẵn ===" << std::endl;
                std::vector<char> buffer(pdfBytes.begin(), pdfBytes.end());
                PoDoFo::VectorStreamDevice outputDevice(buffer);
                PoDoFo::SignDocument(document, outputDevice, signer, signatureField);
                std::cout << "=== 5. Thực hiện ký - SỬ DỤNG PoDoFo::VectorStreamDevice có sẵn END ===" << std::endl;

                // 6. Lấy kết quả và trả về cho Flutter
                std::vector<uint8_t> signed_pdf_bytes(buffer.data(), buffer.data() + buffer.size());
                p_result->Success(flutter::EncodableValue(signed_pdf_bytes));
                std::cout << "=== PDF Signing Completed Successfully ===" << std::endl;
            } catch (const PoDoFo::PdfError& e) {
                std::string error_msg = std::string("PoDoFo Error: ") + e.what();
                std::cerr << error_msg << std::endl;
                p_result->Error("PODOFO_ERROR", error_msg);
            } catch (const std::exception& e) {
                std::string error_msg = std::string("Standard Exception: ") + e.what();
                std::cerr << error_msg << std::endl;
                p_result->Error("STD_EXCEPTION", error_msg);
            } catch (...) {
                std::string error_msg = "Unknown error occurred during PDF signing";
                std::cerr << error_msg << std::endl;
                p_result->Error("UNKNOWN_ERROR", error_msg);
            }
        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }

    // APDU command for PSO:DECIPHER — single short APDU (data ≤ 254 bytes only)
    std::vector<uint8_t> CreateDecipherCommand(const std::vector<uint8_t>& data) {
        // PSO:DECIPHER: CLA=00, INS=2A, P1=80, P2=86
        // Padding indicator byte (0x00) prepended to data
        std::vector<uint8_t> cmd = { 0x00, 0x2A, 0x80, 0x86, (uint8_t)(data.size() + 1), 0x00 };
        cmd.insert(cmd.end(), data.begin(), data.end());
        cmd.push_back(0x00);
        return cmd;
    }

    /// Send PSO:DECIPHER with command chaining for large payloads (RSA-2048/4096).
    ///
    /// OpenPGP smart cards limit short APDU Lc to 255 bytes.
    /// RSA-4096 ciphertext = 512 bytes + 1 padding indicator = 513 bytes → 3 chunks.
    /// Intermediate chunks use CLA=0x10, final chunk uses CLA=0x00.
    std::vector<uint8_t> NfcsignerPlugin::SendChainedDecipher(SCARDHANDLE hCard, const std::vector<uint8_t>& encryptedData, DWORD dwActiveProtocol) {
        // Prepend padding indicator byte (0x00) as required by OpenPGP PSO:DECIPHER
        std::vector<uint8_t> fullData;
        fullData.reserve(1 + encryptedData.size());
        fullData.push_back(0x00);
        fullData.insert(fullData.end(), encryptedData.begin(), encryptedData.end());

        const size_t maxChunkSize = 255;
        std::vector<std::vector<uint8_t>> chunks;
        for (size_t offset = 0; offset < fullData.size(); offset += maxChunkSize) {
            size_t end = std::min(offset + maxChunkSize, fullData.size());
            chunks.emplace_back(fullData.begin() + offset, fullData.begin() + end);
        }

        std::vector<uint8_t> lastResponse;
        for (size_t i = 0; i < chunks.size(); ++i) {
            bool isLast = (i == chunks.size() - 1);
            uint8_t cla = isLast ? 0x00 : 0x10;

            // Build APDU: CLA INS P1 P2 Lc [data] [Le]
            std::vector<uint8_t> apdu;
            apdu.push_back(cla);
            apdu.push_back(0x2A);  // INS: PSO
            apdu.push_back(0x80);  // P1: return plain
            apdu.push_back(0x86);  // P2: input encrypted
            apdu.push_back(static_cast<uint8_t>(chunks[i].size()));  // Lc
            apdu.insert(apdu.end(), chunks[i].begin(), chunks[i].end());
            if (isLast) {
                apdu.push_back(0x00);  // Le: expect max response
            }

            lastResponse = TransmitAndGetResponse(hCard, apdu, dwActiveProtocol);

            if (lastResponse.size() < 2) {
                throw std::runtime_error("PSO:DECIPHER response too short.");
            }

            uint8_t sw1 = lastResponse[lastResponse.size() - 2];
            uint8_t sw2 = lastResponse[lastResponse.size() - 1];

            if (!isLast) {
                // Intermediate chunk: expect 90 00
                if (sw1 != 0x90 || sw2 != 0x00) {
                    std::ostringstream oss;
                    oss << "PSO:DECIPHER command chaining failed at chunk " << (i + 1)
                        << "/" << chunks.size() << " (SW=" << std::hex << (int)sw1 << (int)sw2 << ")";
                    throw std::runtime_error(oss.str());
                }
            } else {
                // Final chunk: expect 90 00
                if (sw1 != 0x90 || sw2 != 0x00) {
                    std::ostringstream oss;
                    oss << "PSO:DECIPHER failed (SW=" << std::hex << (int)sw1 << (int)sw2 << ")";
                    throw std::runtime_error(oss.str());
                }
            }
        }

        // Return data without status bytes
        return std::vector<uint8_t>(lastResponse.begin(), lastResponse.end() - 2);
    }

    void NfcsignerPlugin::HandleDecryptData(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
            auto pin = std::get<std::string>(args->at(flutter::EncodableValue("pin")));
            auto encryptedData = std::get<std::vector<uint8_t>>(args->at(flutter::EncodableValue("encryptedData")));

            auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
            if (select_resp.size() < 2 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Select Applet failed.");
            }

            // Verify PIN with PW1 mode 0x82 for decryption (as per OpenPGP spec)
            auto verify_cmd = CreateVerifyPinCommand(pin);
            // Change P2 from 0x81 to 0x82 for decryption operations
            if (verify_cmd.size() >= 4) {
                verify_cmd[3] = 0x82;
            }
            auto verify_resp = TransmitAndGetResponse(hCard, verify_cmd, dwActiveProtocol);
            if (verify_resp.size() < 2 || verify_resp[verify_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Verify PIN failed.");
            }

            // Use command chaining for large payloads (RSA-2048/4096)
            auto decrypted_data = SendChainedDecipher(hCard, encryptedData, dwActiveProtocol);
            p_result->Success(flutter::EncodableValue(decrypted_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
}  // namespace nfcsigner
