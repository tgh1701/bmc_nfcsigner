#include "include/nfcsigner/nfcsigner_plugin.h"

#include <memory>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef HAVE_PODOFO
#include <podofo/podofo.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
using namespace PoDoFo;
#endif
namespace nfcsigner {

// Static
    void NfcsignerPlugin::RegisterWithRegistrar(flutter::PluginRegistrar* registrar) {
        auto channel = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
                registrar->messenger(), "nfcsigner",
                        &flutter::StandardMethodCodec::GetInstance());

        auto plugin = std::make_unique<NfcsignerPlugin>();

        channel->SetMethodCallHandler(
                [plugin_pointer = plugin.get()](const auto& call, auto result) {
                    plugin_pointer->HandleMethodCall(call, std::move(result));
                });

        registrar->AddPlugin(std::move(plugin));
    }

    NfcsignerPlugin::NfcsignerPlugin() {}

    NfcsignerPlugin::~NfcsignerPlugin() {}

    void NfcsignerPlugin::HandleMethodCall(
            const flutter::MethodCall<flutter::EncodableValue>& method_call,
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
        } else {
            result->NotImplemented();
        }
    }
    // Helper functions (giữ nguyên từ Windows version)
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
        hex_str.reserve(data.size() * 2);

        for (unsigned char byte : data) {
            hex_str += hex_chars[(byte >> 4) & 0x0F];
            hex_str += hex_chars[byte & 0x0F];
        }
        return hex_str;
    }
    // Các hàm tạo APDU command (giữ nguyên)
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
// Wrapper for card operations (sửa cho Linux)
    template<typename Func>
    void CardOperation(Func&& operation, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        SCARDCONTEXT hContext = 0;
        SCARDHANDLE hCard = 0;
        DWORD dwActiveProtocol = 0;

        try {
            LONG lReturn = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
            if (lReturn != SCARD_S_SUCCESS) {
                throw std::runtime_error("SCardEstablishContext failed: " + std::to_string(lReturn));
            }

            DWORD dwReaders = 0;
            lReturn = SCardListReaders(hContext, NULL, NULL, &dwReaders);
            if (lReturn != SCARD_S_SUCCESS || dwReaders == 0) {
                SCardReleaseContext(hContext);
                throw std::runtime_error("No card readers found or SCardListReaders failed");
            }

            std::vector<char> readersBuffer(dwReaders);
            lReturn = SCardListReaders(hContext, NULL, readersBuffer.data(), &dwReaders);
            if (lReturn != SCARD_S_SUCCESS) {
                SCardReleaseContext(hContext);
                throw std::runtime_error("SCardListReaders failed to get reader names");
            }

            // Lấy reader đầu tiên
            std::string readerName = readersBuffer.data();
            if (readerName.empty()) {
                SCardReleaseContext(hContext);
                throw std::runtime_error("No valid reader found");
            }

            lReturn = SCardConnect(hContext, readerName.c_str(), SCARD_SHARE_SHARED,
                                   SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
            if (lReturn != SCARD_S_SUCCESS) {
                SCardReleaseContext(hContext);
                throw std::runtime_error("SCardConnect failed. Is a card inserted? Error: " + std::to_string(lReturn));
            }

            operation(hCard);

        } catch (const std::runtime_error& e) {
            result->Error("PC/SC_ERROR", e.what());
        }

        if (hCard) SCardDisconnect(hCard, SCARD_LEAVE_CARD);
        if (hContext) SCardReleaseContext(hContext);
    }

// Transmit function cho Linux
    std::vector<uint8_t> NfcsignerPlugin::TransmitAndGetResponse(SCARDHANDLE hCard, const std::vector<uint8_t>& command) {
        std::vector<uint8_t> response_buffer(260, 0);
        DWORD response_len = 260;

        SCARD_IO_REQUEST pioSendPci;
        pioSendPci.dwProtocol = SCARD_PROTOCOL_T1;
        pioSendPci.cbPciLength = sizeof(SCARD_IO_REQUEST);

        LONG lReturn = SCardTransmit(hCard, &pioSendPci, command.data(),
                                     (DWORD)command.size(), NULL,
                                     response_buffer.data(), &response_len);
        if (lReturn != SCARD_S_SUCCESS) {
            throw std::runtime_error("SCardTransmit error: " + std::to_string(lReturn));
        }
        response_buffer.resize(response_len);

        // Xử lý GET RESPONSE (giữ nguyên logic từ Windows)
        if (response_len >= 2 && response_buffer[response_len - 2] == 0x61) {
            std::vector<uint8_t> full_response_data;
            if (response_len > 2) {
                full_response_data.insert(full_response_data.end(),
                                          response_buffer.begin(),
                                          response_buffer.end() - 2);
            }

            while (response_buffer[response_len - 2] == 0x61) {
                uint8_t le = response_buffer[response_len - 1];
                std::vector<uint8_t> get_response_cmd = { 0x00, 0xC0, 0x00, 0x00, le };

                response_len = 260;
                response_buffer.assign(260, 0);

                lReturn = SCardTransmit(hCard, &pioSendPci, get_response_cmd.data(),
                                        (DWORD)get_response_cmd.size(), NULL,
                                        response_buffer.data(), &response_len);
                if (lReturn != SCARD_S_SUCCESS) {
                    throw std::runtime_error("GET RESPONSE transmit error: " + std::to_string(lReturn));
                }
                response_buffer.resize(response_len);

                if (response_len > 2) {
                    full_response_data.insert(full_response_data.end(),
                                              response_buffer.begin(),
                                              response_buffer.end() - 2);
                }
            }
            full_response_data.push_back(response_buffer[response_len - 2]);
            full_response_data.push_back(response_buffer[response_len - 1]);
            return full_response_data;
        }

        return response_buffer;
    }

// Các handler methods (giữ nguyên logic từ Windows)
    void NfcsignerPlugin::HandleSign(const flutter::EncodableMap* args,
                                     std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard) {
            // Implementation giống Windows version
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
            auto pin = std::get<std::string>(args->at(flutter::EncodableValue("pin")));
            auto dataToSign = std::get<std::vector<uint8_t>>(args->at(flutter::EncodableValue("dataToSign")));
            auto keyIndex = std::get<int>(args->at(flutter::EncodableValue("keyIndex")));

            auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID));
            if (select_resp.back() != 0x00 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn Applet thất bại.");
            }

            auto verify_resp = TransmitAndGetResponse(hCard, CreateVerifyPinCommand(pin));
            if (verify_resp.back() != 0x00 || verify_resp[verify_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Xác thực PIN thất bại.");
            }

            auto sign_resp = TransmitAndGetResponse(hCard, CreateComputeSignatureCommand(dataToSign, keyIndex));
            if (sign_resp.back() != 0x00 || sign_resp[sign_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Ký số thất bại.");
            }

            std::vector<uint8_t> signature_data(sign_resp.begin(), sign_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(signature_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }

    void NfcsignerPlugin::HandleGetPublicKey(const flutter::EncodableMap* args,
                                             std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard) {
            // Implementation giống Windows version
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
            auto keyRole = std::get<std::string>(args->at(flutter::EncodableValue("keyRole")));

            auto select_cmd = CreateSelectAppletCommand(appletID);
            auto get_key_cmd = CreateGetRsaPublicKeyCommand(keyRole);

            auto select_resp = TransmitAndGetResponse(hCard, select_cmd);
            if (select_resp.size() < 2 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Select Applet failed.");
            }

            auto key_resp = TransmitAndGetResponse(hCard, get_key_cmd);
            if (key_resp.size() < 2 || key_resp[key_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Get Public Key failed.");
            }

            std::vector<uint8_t> key_data(key_resp.begin(), key_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(key_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }

    void NfcsignerPlugin::HandleGetCertificate(const flutter::EncodableMap* args,
                                               std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard) {
            // Implementation giống Windows version
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));

            auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID));
            if (select_resp.back() != 0x00 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn Applet thất bại.");
            }

            auto select_cert_resp = TransmitAndGetResponse(hCard, CreateSelectCertificateCommand());
            if (select_cert_resp.back() != 0x00 || select_cert_resp[select_cert_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn dữ liệu Certificate thất bại.");
            }

            auto cert_resp = TransmitAndGetResponse(hCard, CreateGetCertificateCommand());
            if (cert_resp.back() != 0x00 || cert_resp[cert_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Lấy Certificate thất bại.");
            }

            std::vector<uint8_t> cert_data(cert_resp.begin(), cert_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(cert_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
    void NfcsignerPlugin::HandleSignPdf(const flutter::EncodableMap* args,
                                        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard) {
            try {
#ifdef HAVE_PODOFO
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
                auto signatureLength = std::get<int>(args->at(flutter::EncodableValue("signatureLength")));

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
                auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID));
                if (select_resp.size() < 2 || select_resp[select_resp.size() - 2] != 0x90) throw std::runtime_error("Select Applet failed.");

                std::cout << "Verifying PIN..." << std::endl;
                auto verify_resp = TransmitAndGetResponse(hCard, CreateVerifyPinCommand(pin));
                if (verify_resp.size() < 2 || verify_resp[verify_resp.size() - 2] != 0x90) throw std::runtime_error("Verify PIN failed.");

                std::cout << "Selecting certificate..." << std::endl;
                auto select_cert_resp = TransmitAndGetResponse(hCard, CreateSelectCertificateCommand());
                if (select_cert_resp.size() < 2 || select_cert_resp[select_cert_resp.size() - 2] != 0x90) throw std::runtime_error("Select Certificate data object failed.");

                auto cert_resp = TransmitAndGetResponse(hCard, CreateGetCertificateCommand());
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

                    // Lần 2: Lấy chữ ký thật và điền vào bộ đệm đã được cấp phát sẵn.
                    // 1. Lấy dữ liệu PoDoFo cung cấp và tính hash SHA-256
                    /*
                    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
                    SHA256(reinterpret_cast<const unsigned char*>(hashToSign.data()), hashToSign.size(), digest.data());

                    // 2. Tạo cấu trúc DigestInfo (định danh SHA256 + hash) để gửi cho thẻ
                    const std::vector<uint8_t> digestInfoPrefix = {
                            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
                    };
                    std::vector<uint8_t> data_to_send_to_card = digestInfoPrefix;
                    data_to_send_to_card.insert(data_to_send_to_card.end(), digest.begin(), digest.end());
                    */
                    std::cout << "Real run: Getting signature from card..." << std::endl;
                    auto sign_resp = TransmitAndGetResponse(hCard, CreateComputeSignatureCommand(data_to_send_to_card, keyIndex));
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
#else
                throw std::runtime_error("PoDoFo not available on Linux build");
#endif
            } catch (const std::exception& e) {
                p_result->Error("PDF_SIGN_ERROR", e.what());
            }
        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }

}  // namespace nfcsigner