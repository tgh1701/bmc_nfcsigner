#define NOMINMAX // Ngăn chặn định nghĩa min và max từ windows.h

#include "nfcsigner_plugin.h"

#include <windows.h>
#include <tchar.h>
// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <winscard.h>

#ifdef HAVE_PODOFO
// Include PoDoFo và OpenSSL
// CRITICAL FIX: windows.h defines DrawText to DrawTextW, which corrupts
// PoDoFo's PdfPainter::DrawText declaration
#ifdef DrawText
#undef DrawText
#endif
#include <podofo/podofo.h>
// #include <podofo/private/PdfDeclarationsPrivate.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
// #include <podofo/private/OpenSSLInternal.h>
using namespace PoDoFo;
#endif

namespace nfcsigner {

class CardError : public std::runtime_error {
public:
  CardError(const std::string &code, const std::string &message)
      : std::runtime_error(message), code_(code) {}
  const std::string &code() const noexcept { return code_; }

private:
  std::string code_;
};

bool IsSelectAppletSuccess(const std::vector<uint8_t> &resp) {
  if (resp.size() < 2)
    return false;
  uint8_t sw1 = resp[resp.size() - 2];
  uint8_t sw2 = resp[resp.size() - 1];
  return (sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x61 ||
         (sw1 == 0x69 && sw2 == 0x85);
}

void CheckVerifyPinResponse(const std::vector<uint8_t> &resp) {
  if (resp.size() >= 2 && resp[resp.size() - 2] == 0x90 &&
      resp[resp.size() - 1] == 0x00) {
    return;
  }
  if (resp.size() >= 2 && resp[resp.size() - 2] == 0x63 &&
      resp[resp.size() - 1] >= 0xC0) {
    int triesLeft = resp[resp.size() - 1] - 0xC0;
    if (triesLeft > 0) {
      throw CardError("AUTH_ERROR", "Xác thực PIN thất bại. Còn " +
                                        std::to_string(triesLeft) +
                                        " lần thử.");
    }
  }
  throw CardError("AUTH_ERROR", "Xác thực PIN thất bại.");
}

#ifdef HAVE_PODOFO
// Helper: Create a PoDoFo PdfString from UTF-8, handling Vietnamese/Unicode
// safely. PoDoFo 1.0.x PdfString(string_view) may crash on multi-byte UTF-8. We
// convert to UTF-16BE with BOM prefix (\xFE\xFF) which PDF natively supports.
PoDoFo::PdfString SafePdfString(const std::string &utf8str) {
  if (utf8str.empty())
    return PoDoFo::PdfString();

  // Check if string is pure ASCII - if so, use simple constructor
  bool isAscii = true;
  for (unsigned char c : utf8str) {
    if (c >= 128) {
      isAscii = false;
      break;
    }
  }
  if (isAscii) {
    return PoDoFo::PdfString(utf8str);
  }

  // Convert UTF-8 to UTF-16 (wide string) using Windows API
  int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), -1, NULL, 0);
  if (wlen <= 0)
    return PoDoFo::PdfString(utf8str); // fallback

  std::vector<wchar_t> wstr(wlen);
  MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), -1, wstr.data(), wlen);

  // Build UTF-16BE with BOM (\xFE\xFF prefix) for PDF
  // Exclude null terminator from wstr
  size_t charCount = wlen - 1;
  std::string utf16be;
  utf16be.reserve(2 + charCount * 2);
  utf16be += '\xFE'; // BOM high byte
  utf16be += '\xFF'; // BOM low byte
  for (size_t i = 0; i < charCount; i++) {
    uint16_t ch = static_cast<uint16_t>(wstr[i]);
    utf16be += static_cast<char>((ch >> 8) & 0xFF); // high byte
    utf16be += static_cast<char>(ch & 0xFF);        // low byte
  }

  return PoDoFo::PdfString::FromRaw(
      PoDoFo::bufferview(utf16be.data(), utf16be.size()));
}

// Helper: Convert UTF-8 string to ASCII-safe for font rendering (Helvetica
// can't render Vietnamese)
std::string ToAsciiSafe(const std::string &utf8str) {
  std::string result;
  for (size_t i = 0; i < utf8str.size(); i++) {
    unsigned char c = static_cast<unsigned char>(utf8str[i]);
    if (c < 128) {
      result += static_cast<char>(c);
    } else {
      // Skip continuation bytes of multi-byte UTF-8 sequences
      if ((c & 0xE0) == 0xC0)
        i += 1; // 2-byte sequence
      else if ((c & 0xF0) == 0xE0)
        i += 2; // 3-byte sequence
      else if ((c & 0xF8) == 0xF0)
        i += 3; // 4-byte sequence
      result += '?';
    }
  }
  return result;
}
#endif

// Helper function to convert hex string to byte vector
std::vector<uint8_t> HexToBytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  if (hex.length() % 2 != 0) {
    throw CardError("INVALID_PARAMETERS", "Hex string must have even length");
  }

  for (size_t i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    char *end;
    uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), &end, 16));
    if (*end != '\0') {
      throw CardError("INVALID_PARAMETERS", "Invalid hex character");
    }
    bytes.push_back(byte);
  }
  return bytes;
}

template <typename T> std::string ToHexString(const T &data) {
  const char hex_chars[] = "0123456789abcdef";
  std::string hex_str;
  hex_str.reserve(data.size() * 2);

  for (unsigned char byte : data) {
    hex_str += hex_chars[(byte >> 4) & 0x0F];
    hex_str += hex_chars[byte & 0x0F];
  }

  return hex_str;
}

std::vector<uint8_t> CreateSelectAppletCommand(const std::string &appletID) {
  auto appletID_bytes = HexToBytes(appletID);
  std::vector<uint8_t> cmd = {0x00, 0xA4, 0x04, 0x00,
                              (uint8_t)appletID_bytes.size()};
  cmd.insert(cmd.end(), appletID_bytes.begin(), appletID_bytes.end());
  cmd.push_back(0x00);
  return cmd;
}

std::vector<uint8_t> CreateVerifyPinCommand(const std::string &pin) {
  std::vector<uint8_t> pin_bytes(pin.begin(), pin.end());
  std::vector<uint8_t> cmd = {0x00, 0x20, 0x00, 0x81,
                              (uint8_t)pin_bytes.size()};
  cmd.insert(cmd.end(), pin_bytes.begin(), pin_bytes.end());
  return cmd;
}

std::vector<uint8_t> CreateVerifyDecryptPinCommand(const std::string &pin) {
  std::vector<uint8_t> pin_bytes(pin.begin(), pin.end());
  std::vector<uint8_t> cmd = {0x00, 0x20, 0x00, 0x82,
                              (uint8_t)pin_bytes.size()};
  cmd.insert(cmd.end(), pin_bytes.begin(), pin_bytes.end());
  return cmd;
}

std::vector<uint8_t>
CreateComputeSignatureCommand(const std::vector<uint8_t> &data, int keyIndex) {
  uint8_t p1 = 0x9E;
  uint8_t p2;
  switch (keyIndex) {
  case 1:
    p2 = 0x9B;
    break;
  case 2:
    p2 = 0x9C;
    break;
  default:
    p2 = 0x9A;
    break;
  }
  std::vector<uint8_t> cmd = {0x00, 0x2A, p1, p2, (uint8_t)data.size()};
  cmd.insert(cmd.end(), data.begin(), data.end());
  cmd.push_back(0x00);
  return cmd;
}

std::vector<uint8_t> CreateSelectCertificateCommand() {
  std::vector<uint8_t> data = {0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21};
  std::vector<uint8_t> cmd = {0x00, 0xA5, 0x02, 0x04, (uint8_t)data.size()};
  cmd.insert(cmd.end(), data.begin(), data.end());
  cmd.push_back(0x00);
  return cmd;
}

std::vector<uint8_t> CreateGetRsaPublicKeyCommand(const std::string &keyRole) {
  std::vector<uint8_t> data;
  if (keyRole == "sig")
    data = {0xB6, 0x00};
  else if (keyRole == "dec")
    data = {0xB8, 0x00};
  else if (keyRole == "aut")
    data = {0xA4, 0x00};
  else if (keyRole == "sm")
    data = {0xA6, 0x00};
  else
    throw CardError("INVALID_PARAMETERS", "Invalid key role.");

  std::vector<uint8_t> cmd = {0x00, 0x47, 0x81, 0x00, (uint8_t)data.size()};
  cmd.insert(cmd.end(), data.begin(), data.end());
  cmd.push_back(0x00);
  return cmd;
}

std::vector<uint8_t> CreateGetCertificateCommand() {
  return {0x00, 0xCA, 0x7F, 0x21, 0x00};
}

std::vector<uint8_t> CreateGetPinRetryCounterCommand() {
  return {0x00, 0xCA, 0x00, 0xC4, 0x00};
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
  const auto *args =
      std::get_if<flutter::EncodableMap>(method_call.arguments());

  if (method_call.method_name().compare("isCardReaderAttached") == 0) {
    HandleIsCardReaderAttached(std::move(result));
  } else if (method_call.method_name().compare("cancelNfc") == 0 ||
             method_call.method_name().compare("cancelNfcWait") == 0) {
    result->Success(flutter::EncodableValue(true));
  } else if (method_call.method_name().compare("getPinRetryCounter") == 0) {
    HandleGetPinRetryCounter(args, std::move(result));
  } else if (method_call.method_name().compare("generateSignature") == 0) {
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
    if (IsWindows10OrGreater())
      version_stream << "10+";
    else if (IsWindows8OrGreater())
      version_stream << "8";
    else
      version_stream << "(unknown)";
    result->Success(flutter::EncodableValue(version_stream.str()));
  } else {
    result->NotImplemented();
  }
}

void NfcsignerPlugin::HandleIsCardReaderAttached(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  auto shared_result =
      std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
          result.release());
  std::thread([shared_result]() {
    SCARDCONTEXT hContext = 0;
    bool attached = false;
    LONG lReturn =
        SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
    if (lReturn == SCARD_S_SUCCESS && hContext != 0) {
      DWORD dwReaders = SCARD_AUTOALLOCATE;
      LPTSTR mszReaders = NULL;
      lReturn =
          SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
      if (lReturn == SCARD_S_SUCCESS && mszReaders != NULL) {
        LPCTSTR pReader = mszReaders;
        while (*pReader != '\0') {
          SCARDHANDLE hCard = 0;
          DWORD dwActiveProtocol = 0;
          LONG connectRes = SCardConnect(hContext, pReader, SCARD_SHARE_SHARED,
                                         SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                         &hCard, &dwActiveProtocol);
          if (connectRes == SCARD_S_SUCCESS && hCard != 0) {
            attached = true;
            SCardDisconnect(hCard, SCARD_LEAVE_CARD);
            break;
          }
          pReader += lstrlen(pReader) + 1;
        }
        SCardFreeMemory(hContext, mszReaders);
      }
      SCardReleaseContext(hContext);
    }
    shared_result->Success(flutter::EncodableValue(attached));
  }).detach();
}

// Wrapper for an entire card operation (Runs on a background thread so it NEVER
// blocks the Win32/Flutter UI loop)
template <typename Func>
void CardOperation(
    Func &&operation,
    std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  std::thread([op = std::forward<Func>(operation), result]() mutable {
    SCARDCONTEXT hContext = 0;
    SCARDHANDLE hCard = 0;
    DWORD dwActiveProtocol = 0;

    try {
      LONG lReturn =
          SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
      if (lReturn != SCARD_S_SUCCESS) {
        throw CardError("COMMUNICATION_ERROR", "SCardEstablishContext failed.");
      }

      DWORD dwReaders = SCARD_AUTOALLOCATE;
      LPTSTR mszReaders = NULL;
      lReturn =
          SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
      if (lReturn != SCARD_S_SUCCESS || mszReaders == NULL ||
          mszReaders[0] == '\0') {
        if (mszReaders)
          SCardFreeMemory(hContext, mszReaders);
        throw CardError("COMMUNICATION_ERROR",
                        "Không tìm thấy đầu đọc thẻ thông minh.");
      }

      // Collect all reader names from the multi-string
      std::vector<std::basic_string<TCHAR>> readers;
      LPCTSTR pReader = mszReaders;
      while (*pReader != '\0') {
        readers.emplace_back(pReader);
        pReader += lstrlen(pReader) + 1;
      }
      SCardFreeMemory(hContext, mszReaders);

      if (readers.empty()) {
        throw CardError("COMMUNICATION_ERROR",
                        "Không tìm thấy đầu đọc thẻ thông minh.");
      }

      std::string lastErrorCode = "COMMUNICATION_ERROR";
      std::string lastErrorMsg = "Không thể kết nối với thẻ thông minh.";

      for (size_t i = 0; i < readers.size(); ++i) {
        hCard = 0;
        dwActiveProtocol = 0;
        lReturn = SCardConnect(hContext, readers[i].c_str(), SCARD_SHARE_SHARED,
                               SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard,
                               &dwActiveProtocol);
        if (lReturn != SCARD_S_SUCCESS || hCard == 0) {
          continue;
        }

        try {
          std::cout << "[CardOperation] Connected to reader #" << i
                    << " with protocol: "
                    << (dwActiveProtocol == SCARD_PROTOCOL_T0 ? "T0" : "T1")
                    << std::endl;
          op(hCard, dwActiveProtocol);
          SCardDisconnect(hCard, SCARD_LEAVE_CARD);
          hCard = 0;
          SCardReleaseContext(hContext);
          hContext = 0;
          return;
        } catch (const CardError &ce) {
          SCardDisconnect(hCard, SCARD_LEAVE_CARD);
          hCard = 0;
          lastErrorCode = ce.code();
          lastErrorMsg = ce.what();
          // Nếu lỗi chọn Applet và máy còn đầu đọc khác (ví dụ đầu đọc
          // ảo/Windows Hello), thử tiếp đầu đọc kế
          if (ce.code() == "APPLET_NOT_SELECTED" && (i + 1) < readers.size()) {
            continue;
          }
          throw;
        }
      }

      throw CardError(lastErrorCode, lastErrorMsg);

    } catch (const CardError &e) {
      result->Error(e.code(), e.what());
    } catch (const std::runtime_error &e) {
      result->Error("COMMUNICATION_ERROR", e.what());
    } catch (const std::exception &e) {
      result->Error("COMMUNICATION_ERROR", e.what());
    } catch (...) {
      result->Error("UNKNOWN_ERROR",
                    "Unknown exception during smart card operation");
    }

    if (hCard)
      SCardDisconnect(hCard, SCARD_LEAVE_CARD);
    if (hContext)
      SCardReleaseContext(hContext);
  }).detach();
}

// APDU Transmit function with GET RESPONSE handling
std::vector<uint8_t>
NfcsignerPlugin::TransmitAndGetResponse(SCARDHANDLE hCard,
                                        const std::vector<uint8_t> &command,
                                        DWORD dwActiveProtocol) {

  const SCARD_IO_REQUEST *pci =
      (dwActiveProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;

  const DWORD BUFFER_SIZE = 4096;
  std::vector<uint8_t> response_buffer(BUFFER_SIZE, 0);
  DWORD response_len = BUFFER_SIZE;

  LONG lReturn =
      SCardTransmit(hCard, pci, command.data(), (DWORD)command.size(), NULL,
                    response_buffer.data(), &response_len);
  if (lReturn != SCARD_S_SUCCESS) {
    std::ostringstream oss;
    oss << "SCardTransmit failed (0x" << std::hex << lReturn << ")";
    throw CardError("COMMUNICATION_ERROR", oss.str());
  }
  response_buffer.resize(response_len);

  if (response_len >= 2 && response_buffer[response_len - 2] == 0x61) {
    std::vector<uint8_t> full_response_data;
    if (response_len > 2) {
      full_response_data.insert(full_response_data.end(),
                                response_buffer.begin(),
                                response_buffer.end() - 2);
    }

    while (response_len >= 2 && response_buffer[response_len - 2] == 0x61) {
      uint8_t le = response_buffer[response_len - 1];
      std::vector<uint8_t> get_response_cmd = {0x00, 0xC0, 0x00, 0x00, le};

      response_len = BUFFER_SIZE;
      response_buffer.assign(BUFFER_SIZE, 0);

      lReturn = SCardTransmit(hCard, pci, get_response_cmd.data(),
                              (DWORD)get_response_cmd.size(), NULL,
                              response_buffer.data(), &response_len);
      if (lReturn != SCARD_S_SUCCESS) {
        throw CardError("COMMUNICATION_ERROR",
                        "SCardTransmit failed during GET RESPONSE.");
      }
      response_buffer.resize(response_len);

      if (response_len > 2) {
        full_response_data.insert(full_response_data.end(),
                                  response_buffer.begin(),
                                  response_buffer.end() - 2);
      }
    }
    if (response_len >= 2) {
      full_response_data.push_back(response_buffer[response_len - 2]);
      full_response_data.push_back(response_buffer[response_len - 1]);
    }
    return full_response_data;
  }

  return response_buffer;
}

void NfcsignerPlugin::HandleGetPinRetryCounter(
    const flutter::EncodableMap *args,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  flutter::EncodableMap copied_args =
      (args != nullptr) ? *args : flutter::EncodableMap();
  auto shared_result =
      std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
          result.release());
  CardOperation(
      [this, copied_args = std::move(copied_args),
       shared_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
        auto appletID = std::get<std::string>(
            copied_args.at(flutter::EncodableValue("appletID")));

        auto select_resp = TransmitAndGetResponse(
            hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
        if (!IsSelectAppletSuccess(select_resp)) {
          throw CardError("APPLET_NOT_SELECTED", "Chọn Applet thất bại.");
        }

        auto resp = TransmitAndGetResponse(
            hCard, CreateGetPinRetryCounterCommand(), dwActiveProtocol);
        if (resp.size() < 2 || resp[resp.size() - 2] != 0x90 ||
            resp[resp.size() - 1] != 0x00) {
          throw CardError("OPERATION_NOT_SUPPORTED",
                          "Thẻ không trả PW status bytes.");
        }

        std::vector<uint8_t> data(resp.begin(), resp.end() - 2);
        if (data.size() >= 2 && data[0] == 0xC4) {
          size_t len = data[1];
          if (data.size() >= 2 + len) {
            data.assign(data.begin() + 2, data.begin() + 2 + len);
          }
        }
        if (data.size() < 5) {
          throw CardError("OPERATION_NOT_SUPPORTED",
                          "Dữ liệu PW status quá ngắn.");
        }
        int retryCounter = static_cast<int>(data[4]);
        shared_result->Success(flutter::EncodableValue(retryCounter));
      },
      shared_result);
}

void NfcsignerPlugin::HandleSign(
    const flutter::EncodableMap *args,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  flutter::EncodableMap copied_args =
      (args != nullptr) ? *args : flutter::EncodableMap();
  auto shared_result =
      std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
          result.release());
  CardOperation(
      [this, copied_args = std::move(copied_args),
       shared_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
        auto appletID = std::get<std::string>(
            copied_args.at(flutter::EncodableValue("appletID")));
        auto pin = std::get<std::string>(
            copied_args.at(flutter::EncodableValue("pin")));
        auto dataToSign = std::get<std::vector<uint8_t>>(
            copied_args.at(flutter::EncodableValue("dataToSign")));
        auto keyIndex =
            std::get<int>(copied_args.at(flutter::EncodableValue("keyIndex")));

        auto select_resp = TransmitAndGetResponse(
            hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
        if (!IsSelectAppletSuccess(select_resp)) {
          throw CardError("APPLET_NOT_SELECTED", "Chọn Applet thất bại.");
        }

        auto verify_resp = TransmitAndGetResponse(
            hCard, CreateVerifyPinCommand(pin), dwActiveProtocol);
        CheckVerifyPinResponse(verify_resp);

        auto sign_resp = TransmitAndGetResponse(
            hCard, CreateComputeSignatureCommand(dataToSign, keyIndex),
            dwActiveProtocol);
        if (sign_resp.size() < 2 || sign_resp.back() != 0x00 ||
            sign_resp[sign_resp.size() - 2] != 0x90) {
          throw CardError("OPERATION_NOT_SUPPORTED", "Ký số thất bại.");
        }

        std::vector<uint8_t> signature_data(sign_resp.begin(),
                                            sign_resp.end() - 2);
        shared_result->Success(flutter::EncodableValue(signature_data));
      },
      shared_result);
}

void NfcsignerPlugin::HandleGetPublicKey(
    const flutter::EncodableMap *args,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  flutter::EncodableMap copied_args =
      (args != nullptr) ? *args : flutter::EncodableMap();
  auto shared_result =
      std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
          result.release());
  CardOperation(
      [this, copied_args = std::move(copied_args),
       shared_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
        auto appletID = std::get<std::string>(
            copied_args.at(flutter::EncodableValue("appletID")));
        auto keyRole = std::get<std::string>(
            copied_args.at(flutter::EncodableValue("keyRole")));

        auto select_cmd = CreateSelectAppletCommand(appletID);
        auto get_key_cmd = CreateGetRsaPublicKeyCommand(keyRole);

        auto select_resp =
            TransmitAndGetResponse(hCard, select_cmd, dwActiveProtocol);
        if (!IsSelectAppletSuccess(select_resp)) {
          throw CardError("APPLET_NOT_SELECTED", "Chọn Applet thất bại.");
        }

        auto key_resp =
            TransmitAndGetResponse(hCard, get_key_cmd, dwActiveProtocol);
        if (key_resp.size() < 2 || key_resp[key_resp.size() - 2] != 0x90) {
          throw CardError("OPERATION_NOT_SUPPORTED",
                          "Không thể lấy khóa công khai.");
        }

        std::vector<uint8_t> key_data(key_resp.begin(), key_resp.end() - 2);
        shared_result->Success(flutter::EncodableValue(key_data));
      },
      shared_result);
}

void NfcsignerPlugin::HandleGetCertificate(
    const flutter::EncodableMap *args,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  flutter::EncodableMap copied_args =
      (args != nullptr) ? *args : flutter::EncodableMap();
  auto shared_result =
      std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
          result.release());
  CardOperation(
      [this, copied_args = std::move(copied_args),
       shared_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
        auto appletID = std::get<std::string>(
            copied_args.at(flutter::EncodableValue("appletID")));

        auto select_resp = TransmitAndGetResponse(
            hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
        if (!IsSelectAppletSuccess(select_resp)) {
          throw CardError("APPLET_NOT_SELECTED", "Chọn Applet thất bại.");
        }

        auto select_cert_resp = TransmitAndGetResponse(
            hCard, CreateSelectCertificateCommand(), dwActiveProtocol);
        if (select_cert_resp.size() < 2 || select_cert_resp.back() != 0x00 ||
            select_cert_resp[select_cert_resp.size() - 2] != 0x90) {
          throw CardError("OPERATION_NOT_SUPPORTED",
                          "Chọn dữ liệu Certificate thất bại.");
        }

        auto cert_resp = TransmitAndGetResponse(
            hCard, CreateGetCertificateCommand(), dwActiveProtocol);
        if (cert_resp.size() < 2 || cert_resp.back() != 0x00 ||
            cert_resp[cert_resp.size() - 2] != 0x90) {
          throw CardError("OPERATION_NOT_SUPPORTED",
                          "Lấy Certificate thất bại.");
        }

        std::vector<uint8_t> cert_data(cert_resp.begin(), cert_resp.end() - 2);
        shared_result->Success(flutter::EncodableValue(cert_data));
      },
      shared_result);
}

void NfcsignerPlugin::HandleSignPdf(
    const flutter::EncodableMap *args,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {

  flutter::EncodableMap copied_args =
      (args != nullptr) ? *args : flutter::EncodableMap();
  auto shared_result =
      std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
          result.release());

  CardOperation(
      [this, copied_args = std::move(copied_args),
       shared_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
        try {
          // 1. Lấy tất cả tham số từ Flutter
          std::cout << "=== Starting PDF Signing Process ===" << std::endl;
          std::cout << "PoDoFo version: " << PODOFO_VERSION_STRING << std::endl;
          auto pdfBytes = std::get<std::vector<uint8_t>>(
              copied_args.at(flutter::EncodableValue("pdfBytes")));
          auto appletID = std::get<std::string>(
              copied_args.at(flutter::EncodableValue("appletID")));
          auto pin = std::get<std::string>(
              copied_args.at(flutter::EncodableValue("pin")));
          auto keyIndex = std::get<int>(
              copied_args.at(flutter::EncodableValue("keyIndex")));
          std::string reason = "Approved";
          auto reason_iter =
              copied_args.find(flutter::EncodableValue("reason"));
          if (reason_iter != copied_args.end() &&
              std::holds_alternative<std::string>(reason_iter->second)) {
            reason = std::get<std::string>(reason_iter->second);
          }
          std::string location = "Hanoi";
          auto location_iter =
              copied_args.find(flutter::EncodableValue("location"));
          if (location_iter != copied_args.end() &&
              std::holds_alternative<std::string>(location_iter->second)) {
            location = std::get<std::string>(location_iter->second);
          }
          int signatureLength = 512;
          auto sigLen_iter =
              copied_args.find(flutter::EncodableValue("signatureLength"));
          if (sigLen_iter != copied_args.end()) {
            signatureLength = std::get<int>(sigLen_iter->second);
          }

          auto data_to_send_to_card = std::get<std::vector<uint8_t>>(
              copied_args.at(flutter::EncodableValue("pdfHashBytes")));
          if (data_to_send_to_card.empty()) {
            throw CardError("INVALID_PARAMETERS",
                            "pdfHashBytes cannot be empty.");
          }
          double x = 50.0, y = 700.0, width = 200.0, height = 50.0;
          int pageNumber = 1;
          std::string contact = "info@bmctech.vn";
          std::string signerName = "BMC T&S JSC";

          auto config_iter =
              copied_args.find(flutter::EncodableValue("signatureConfig"));
          std::vector<uint8_t> signatureImageBytes;
          double signatureImageWidth = 50.0, signatureImageHeight = 50.0;
          std::string signDate;
          if (config_iter != copied_args.end() &&
              std::holds_alternative<flutter::EncodableMap>(
                  config_iter->second)) {
            auto signatureConfig =
                std::get<flutter::EncodableMap>(config_iter->second);

            auto x_iter = signatureConfig.find(flutter::EncodableValue("x"));
            auto y_iter = signatureConfig.find(flutter::EncodableValue("y"));
            auto width_iter =
                signatureConfig.find(flutter::EncodableValue("width"));
            auto height_iter =
                signatureConfig.find(flutter::EncodableValue("height"));
            auto page_iter =
                signatureConfig.find(flutter::EncodableValue("pageNumber"));
            auto contact_iter =
                signatureConfig.find(flutter::EncodableValue("contact"));
            auto signerName_iter =
                signatureConfig.find(flutter::EncodableValue("signerName"));
            auto signatureImage_iter =
                signatureConfig.find(flutter::EncodableValue("signatureImage"));
            auto signatureImageWidth_iter = signatureConfig.find(
                flutter::EncodableValue("signatureImageWidth"));
            auto signatureImageHeight_iter = signatureConfig.find(
                flutter::EncodableValue("signatureImageHeight"));
            auto signDate_iter =
                signatureConfig.find(flutter::EncodableValue("signDate"));

            if (x_iter != signatureConfig.end() &&
                std::holds_alternative<double>(x_iter->second))
              x = std::get<double>(x_iter->second);
            if (y_iter != signatureConfig.end() &&
                std::holds_alternative<double>(y_iter->second))
              y = std::get<double>(y_iter->second);
            if (width_iter != signatureConfig.end() &&
                std::holds_alternative<double>(width_iter->second))
              width = std::get<double>(width_iter->second);
            if (height_iter != signatureConfig.end() &&
                std::holds_alternative<double>(height_iter->second))
              height = std::get<double>(height_iter->second);
            if (page_iter != signatureConfig.end() &&
                std::holds_alternative<int>(page_iter->second))
              pageNumber = std::get<int>(page_iter->second);
            if (contact_iter != signatureConfig.end() &&
                std::holds_alternative<std::string>(contact_iter->second))
              contact = std::get<std::string>(contact_iter->second);
            if (signerName_iter != signatureConfig.end() &&
                std::holds_alternative<std::string>(signerName_iter->second))
              signerName = std::get<std::string>(signerName_iter->second);
            if (signatureImage_iter != signatureConfig.end() &&
                std::holds_alternative<std::vector<uint8_t>>(
                    signatureImage_iter->second))
              signatureImageBytes =
                  std::get<std::vector<uint8_t>>(signatureImage_iter->second);
            if (signatureImageWidth_iter != signatureConfig.end() &&
                std::holds_alternative<double>(
                    signatureImageWidth_iter->second))
              signatureImageWidth =
                  std::get<double>(signatureImageWidth_iter->second);
            if (signatureImageHeight_iter != signatureConfig.end() &&
                std::holds_alternative<double>(
                    signatureImageHeight_iter->second))
              signatureImageHeight =
                  std::get<double>(signatureImageHeight_iter->second);
            if (signDate_iter != signatureConfig.end() &&
                std::holds_alternative<std::string>(signDate_iter->second)) {
              signDate = std::get<std::string>(signDate_iter->second);
              if (signDate.length() >= 19 && signDate[4] == '-' &&
                  signDate[7] == '-') {
                std::string yyyy = signDate.substr(0, 4);
                std::string mm = signDate.substr(5, 2);
                std::string dd = signDate.substr(8, 2);
                std::string time = signDate.substr(11, 8);
                signDate = dd + "/" + mm + "/" + yyyy + " " + time;
              }
            }
          }

          // 2. Giao tiếp với thẻ để lấy Certificate
          std::cout << "Selecting applet..." << std::endl;
          auto select_resp = TransmitAndGetResponse(
              hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
          if (!IsSelectAppletSuccess(select_resp)) {
            throw CardError("APPLET_NOT_SELECTED", "Chọn Applet thất bại.");
          }

          std::cout << "Verifying PIN..." << std::endl;
          auto verify_resp = TransmitAndGetResponse(
              hCard, CreateVerifyPinCommand(pin), dwActiveProtocol);
          CheckVerifyPinResponse(verify_resp);

          std::cout << "Selecting certificate..." << std::endl;
          auto select_cert_resp = TransmitAndGetResponse(
              hCard, CreateSelectCertificateCommand(), dwActiveProtocol);
          if (select_cert_resp.size() < 2 ||
              select_cert_resp[select_cert_resp.size() - 2] != 0x90) {
            throw CardError("OPERATION_NOT_SUPPORTED",
                            "Chọn dữ liệu Certificate thất bại.");
          }

          auto cert_resp = TransmitAndGetResponse(
              hCard, CreateGetCertificateCommand(), dwActiveProtocol);
          if (cert_resp.size() < 2 || cert_resp[cert_resp.size() - 2] != 0x90) {
            throw CardError("OPERATION_NOT_SUPPORTED",
                            "Lấy Certificate thất bại.");
          }
          std::vector<uint8_t> certificate_data(cert_resp.begin(),
                                                cert_resp.end() - 2);
          if (certificate_data.empty()) {
            throw CardError("OPERATION_NOT_SUPPORTED",
                            "Certificate từ thẻ bị rỗng.");
          }

          // 3. Chuẩn bị tài liệu PDF và trường chữ ký bằng PoDoFo API mới
          PoDoFo::PdfMemDocument document;
          document.LoadFromBuffer(PoDoFo::bufferview(
              reinterpret_cast<const char *>(pdfBytes.data()),
              pdfBytes.size()));

          PoDoFo::PdfPage &page = document.GetPages().GetPageAt(
              pageNumber > 0 ? pageNumber - 1 : 0);

          Rect annot_rect = PoDoFo::Rect(x, y, width, height);
          auto &signatureField = page.CreateField<PoDoFo::PdfSignature>(
              "BMC-Signature", annot_rect);
          PdfDate dateString = PoDoFo::PdfDate::LocalNow();
          signatureField.SetSignatureReason(SafePdfString(reason));
          signatureField.SetSignatureLocation(SafePdfString(location));
          signatureField.SetSignerName(SafePdfString(signerName));
          signatureField.SetSignatureDate(dateString);

          PoDoFo::Rect local_bbox(0, 0, width, height);
          auto sigXObject = document.CreateXObjectForm(local_bbox);

          if (sigXObject) {
            PoDoFo::PdfPainter painter;
            painter.SetCanvas(*sigXObject);
            PoDoFo::PdfColor black(0.0, 0.0, 0.0);
            painter.GraphicsState.SetStrokingColor(black);
            painter.GraphicsState.SetLineWidth(1.0);

            const bool hasImage = !signatureImageBytes.empty();
            const bool hasText = !signerName.empty();

            double img_w = 0.0;
            double img_h = 0.0;
            double img_x = 4.0;
            double img_y = 0.0;
            std::shared_ptr<PoDoFo::PdfImage> image = nullptr;

            if (hasImage) {
              try {
                image = document.CreateImage();
                image->LoadFromBuffer(PoDoFo::bufferview(
                    reinterpret_cast<const char *>(signatureImageBytes.data()),
                    signatureImageBytes.size()));
                if (image->GetWidth() > 0 && image->GetHeight() > 0) {
                  img_w = signatureImageWidth > 0 ? signatureImageWidth : 60.0;
                  img_h =
                      signatureImageHeight > 0 ? signatureImageHeight : 50.0;

                  if (hasText) {
                    double max_w = (std::min)(width * 0.35,
                                              (std::max)(10.0, width - 90.0));
                    if (img_w > max_w) {
                      double ratio = max_w / img_w;
                      img_w = max_w;
                      img_h *= ratio;
                    }
                    if (img_h > height - 6.0) {
                      double ratio = (height - 6.0) / img_h;
                      img_h = height - 6.0;
                      img_w *= ratio;
                    }
                    img_x = 4.0;
                    img_y = (height - img_h) / 2.0;
                  } else {
                    if (img_w > width - 8.0) {
                      double ratio = (width - 8.0) / img_w;
                      img_w = width - 8.0;
                      img_h *= ratio;
                    }
                    if (img_h > height - 6.0) {
                      double ratio = (height - 6.0) / img_h;
                      img_h = height - 6.0;
                      img_w *= ratio;
                    }
                    img_x = (width - img_w) / 2.0;
                    img_y = (height - img_h) / 2.0;
                  }

                  double scale_x = img_w / image->GetWidth();
                  double scale_y = img_h / image->GetHeight();
                  painter.DrawImage(*image, img_x, img_y, scale_x, scale_y);
                }
              } catch (const PoDoFo::PdfError &e) {
                std::cerr << "Warning: Cannot load signature image: "
                          << e.what() << std::endl;
              }
            }

            if (hasText) {
              try {
                auto &font = document.GetFonts().GetOrCreateFont(
                    "C:\\Windows\\Fonts\\arial.ttf");

                double text_x =
                    hasImage && (img_w > 0) ? (img_x + img_w + 6.0) : 4.0;
                double available_w = width - text_x - 4.0;
                if (available_w < 20.0)
                  available_w = 20.0;

                std::vector<std::string> rawLines;
                rawLines.push_back("Người ký: " + signerName);
                if (!signDate.empty()) {
                  rawLines.push_back("Ngày ký: " + signDate);
                }
                if (!reason.empty() && reason != "Approved" &&
                    reason != "Ký duyệt!") {
                  rawLines.push_back("Lý do: " + reason);
                }

                double baseFontSize = 8.5;
                if (height < 45.0)
                  baseFontSize = 7.0;
                else if (height > 90.0)
                  baseFontSize = 10.0;

                painter.TextState.SetFont(font, baseFontSize);

                double maxLineLen = 0.0;
                for (const auto &l : rawLines) {
                  double len = font.GetStringLength(l, painter.TextState);
                  if (len > maxLineLen)
                    maxLineLen = len;
                }

                double fontSize = baseFontSize;
                if (maxLineLen > available_w && maxLineLen > 0.0) {
                  double scaleRatio = available_w / maxLineLen;
                  if (scaleRatio >= 0.75) {
                    fontSize = (std::max)(6.5, baseFontSize * scaleRatio);
                    painter.TextState.SetFont(font, fontSize);
                  } else {
                    fontSize = 7.0;
                    painter.TextState.SetFont(font, fontSize);
                  }
                }

                auto truncateToFit = [&](const std::string &str,
                                         double max_w) -> std::string {
                  if (font.GetStringLength(str, painter.TextState) <= max_w)
                    return str;
                  std::string ellipsis = "...";
                  double ellipsisLen =
                      font.GetStringLength(ellipsis, painter.TextState);
                  if (ellipsisLen >= max_w)
                    return "";

                  std::string s = str;
                  while (!s.empty()) {
                    while (!s.empty() && (static_cast<unsigned char>(s.back()) &
                                          0xC0) == 0x80) {
                      s.pop_back();
                    }
                    if (!s.empty()) {
                      s.pop_back();
                    }
                    if (font.GetStringLength(s + ellipsis, painter.TextState) <=
                        max_w) {
                      return s + ellipsis;
                    }
                  }
                  return "";
                };

                auto wrapLine = [&](const std::string &text,
                                    double max_w) -> std::vector<std::string> {
                  std::vector<std::string> res;
                  if (text.empty())
                    return res;
                  if (font.GetStringLength(text, painter.TextState) <= max_w) {
                    res.push_back(text);
                    return res;
                  }
                  std::istringstream iss(text);
                  std::string word;
                  std::string currentLine;
                  while (iss >> word) {
                    std::string candidate =
                        currentLine.empty() ? word : (currentLine + " " + word);
                    if (font.GetStringLength(candidate, painter.TextState) <=
                        max_w) {
                      currentLine = candidate;
                    } else {
                      if (!currentLine.empty()) {
                        res.push_back(currentLine);
                        currentLine = word;
                      } else {
                        res.push_back(word);
                        currentLine.clear();
                      }
                    }
                  }
                  if (!currentLine.empty()) {
                    res.push_back(currentLine);
                  }
                  return res;
                };

                std::vector<std::string> lines;
                for (const auto &rawL : rawLines) {
                  auto wrapped = wrapLine(rawL, available_w);
                  lines.insert(lines.end(), wrapped.begin(), wrapped.end());
                }

                for (auto &l : lines) {
                  if (font.GetStringLength(l, painter.TextState) >
                      available_w) {
                    l = truncateToFit(l, available_w);
                  }
                }

                double lineHeight = fontSize * 1.30;
                double totalTextHeight = lines.size() * lineHeight;
                if (totalTextHeight > height - 4.0 && !lines.empty()) {
                  double maxLineHeight = (height - 4.0) / lines.size();
                  if (maxLineHeight < lineHeight) {
                    fontSize = (std::max)(5.5, maxLineHeight / 1.25);
                    painter.TextState.SetFont(font, fontSize);
                    lineHeight = fontSize * 1.25;
                    totalTextHeight = lines.size() * lineHeight;
                  }
                }

                int maxAllowedLines =
                    (std::max)(1, static_cast<int>((height - 4.0) /
                                                   (fontSize * 1.2)));
                if (static_cast<int>(lines.size()) > maxAllowedLines) {
                  lines.resize(maxAllowedLines);
                  totalTextHeight = lines.size() * lineHeight;
                }

                double start_y = (height + totalTextHeight) / 2.0 - fontSize;
                if (start_y > height - 3.0)
                  start_y = height - 3.0;

                double current_y = start_y;
                for (const auto &line : lines) {
                  painter.DrawText(line, text_x, current_y);
                  current_y -= lineHeight;
                }
              } catch (const std::exception &e) {
                std::cout << "[DEBUG] Failed to draw text: " << e.what()
                          << std::endl;
              }
            }

            painter.FinishDrawing();
            signatureField.MustGetWidget().SetAppearanceStream(*sigXObject);
          }

          // 4. Cấu hình PdfSignerCms với callback để ký bằng thẻ
          PoDoFo::PdfSignerCmsParams params;
          params.Hashing = PoDoFo::PdfHashingAlgorithm::SHA256;
          params.Flags = static_cast<PoDoFo::PdfSignerCmsFlags>(
              static_cast<int>(PoDoFo::PdfSignerCmsFlags::ServiceDoDryRun) |
              static_cast<int>(PoDoFo::PdfSignerCmsFlags::ServiceDoWrapDigest));

          params.SigningService = [&](PoDoFo::bufferview hashToSign,
                                      bool dryrun,
                                      PoDoFo::charbuff &signedHash) {
            if (dryrun) {
              signedHash.resize(signatureLength);
              return;
            }

            std::vector<uint8_t> hash_to_sign_vec;
            if (!hashToSign.empty()) {
              hash_to_sign_vec.assign(hashToSign.begin(), hashToSign.end());
            } else {
              hash_to_sign_vec = data_to_send_to_card;
            }

            auto sign_resp = TransmitAndGetResponse(
                hCard,
                CreateComputeSignatureCommand(hash_to_sign_vec, keyIndex),
                dwActiveProtocol);
            if (sign_resp.size() < 2 ||
                sign_resp[sign_resp.size() - 2] != 0x90) {
              throw CardError("OPERATION_NOT_SUPPORTED",
                              "Compute signature failed on card.");
            }

            std::vector<uint8_t> signature_raw(sign_resp.begin(),
                                               sign_resp.end() - 2);
            if (signature_raw.empty()) {
              throw CardError("OPERATION_NOT_SUPPORTED",
                              "Card returned an empty signature.");
            }

            signedHash.assign(
                reinterpret_cast<const char *>(signature_raw.data()),
                signature_raw.size());
          };

          PoDoFo::PdfSignerCms signer(
              PoDoFo::bufferview(
                  reinterpret_cast<const char *>(certificate_data.data()),
                  certificate_data.size()),
              params);

          // 5. Thực hiện ký
          std::vector<char> buffer;
          {
            PoDoFo::VectorStreamDevice outputDevice(buffer);
            outputDevice.Write(reinterpret_cast<const char *>(pdfBytes.data()),
                               pdfBytes.size());
            PoDoFo::SignDocument(document, outputDevice, signer,
                                 signatureField);
          }

          // 6. Lấy kết quả và trả về cho Flutter
          std::vector<uint8_t> signed_pdf_bytes(buffer.begin(), buffer.end());
          shared_result->Success(flutter::EncodableValue(signed_pdf_bytes));
        } catch (const CardError &) {
          throw; // Rethrow to CardOperation so it can try next reader or report
                 // exact CardError code
        } catch (const PoDoFo::PdfError &e) {
          std::string error_msg = std::string("PoDoFo Error: ") + e.what();
          std::cerr << error_msg << std::endl;
          shared_result->Error("PODOFO_ERROR", error_msg);
        }
      },
      shared_result);
}

// Build a single PSO:DECIPHER APDU chunk.
std::vector<uint8_t>
CreateDecipherChunkCommand(const std::vector<uint8_t> &data, bool isLast) {
  std::vector<uint8_t> cmd = {(uint8_t)(isLast ? 0x00 : 0x10), 0x2A, 0x80, 0x86,
                              (uint8_t)data.size()};
  cmd.insert(cmd.end(), data.begin(), data.end());
  if (isLast) {
    cmd.push_back(0x00); // Le — expect decrypted block
  }
  return cmd;
}

std::vector<uint8_t>
NfcsignerPlugin::SendChainedDecipher(SCARDHANDLE hCard,
                                     const std::vector<uint8_t> &encryptedData,
                                     DWORD dwActiveProtocol) {
  if (encryptedData.empty()) {
    throw CardError("INVALID_PARAMETERS",
                    "Decryption failed: encrypted data is empty.");
  }

  std::vector<uint8_t> fullData;
  fullData.reserve(encryptedData.size() + 1);
  fullData.push_back(0x00); // PKCS#1 v1.5 padding indicator
  fullData.insert(fullData.end(), encryptedData.begin(), encryptedData.end());

  const size_t kChunkSize = 255;
  size_t offset = 0;
  std::vector<uint8_t> finalResponse;

  while (offset < fullData.size()) {
    const size_t chunkLen = (std::min)(fullData.size() - offset, kChunkSize);
    const bool isLast = (offset + chunkLen) >= fullData.size();

    std::vector<uint8_t> chunk(fullData.begin() + offset,
                               fullData.begin() + offset + chunkLen);
    auto resp = TransmitAndGetResponse(
        hCard, CreateDecipherChunkCommand(chunk, isLast), dwActiveProtocol);

    if (resp.size() < 2) {
      throw CardError("DECRYPT_ERROR",
                      "Decryption failed: empty card response.");
    }

    const uint8_t sw1 = resp[resp.size() - 2];
    const uint8_t sw2 = resp[resp.size() - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
      std::vector<uint8_t> sw = {sw1, sw2};
      throw CardError("DECRYPT_ERROR",
                      "Decryption failed: SW=0x" + ToHexString(sw));
    }

    if (isLast) {
      finalResponse = std::move(resp);
    }
    offset += chunkLen;
  }

  return finalResponse;
}

void NfcsignerPlugin::HandleDecryptData(
    const flutter::EncodableMap *args,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  flutter::EncodableMap copied_args =
      (args != nullptr) ? *args : flutter::EncodableMap();
  auto shared_result =
      std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
          result.release());
  CardOperation(
      [this, copied_args = std::move(copied_args),
       shared_result](SCARDHANDLE hCard, DWORD dwActiveProtocol) {
        auto appletID = std::get<std::string>(
            copied_args.at(flutter::EncodableValue("appletID")));
        auto pin = std::get<std::string>(
            copied_args.at(flutter::EncodableValue("pin")));
        auto encryptedData = std::get<std::vector<uint8_t>>(
            copied_args.at(flutter::EncodableValue("encryptedData")));

        auto select_resp = TransmitAndGetResponse(
            hCard, CreateSelectAppletCommand(appletID), dwActiveProtocol);
        if (!IsSelectAppletSuccess(select_resp)) {
          throw CardError("APPLET_NOT_SELECTED", "Chọn Applet thất bại.");
        }

        auto verify_resp = TransmitAndGetResponse(
            hCard, CreateVerifyDecryptPinCommand(pin), dwActiveProtocol);
        CheckVerifyPinResponse(verify_resp);

        auto decrypt_resp =
            SendChainedDecipher(hCard, encryptedData, dwActiveProtocol);
        if (decrypt_resp.size() < 2 ||
            decrypt_resp[decrypt_resp.size() - 2] != 0x90) {
          throw CardError("DECRYPT_ERROR", "Giải mã thất bại.");
        }

        std::vector<uint8_t> decrypted_data(decrypt_resp.begin(),
                                            decrypt_resp.end() - 2);
        shared_result->Success(flutter::EncodableValue(decrypted_data));
      },
      shared_result);
}
} // namespace nfcsigner
