#ifndef FLUTTER_PLUGIN_NFCSIGNER_PLUGIN_H_
#define FLUTTER_PLUGIN_NFCSIGNER_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/encodable_value.h>
#include <windows.h> // Cần cho SCARDHANDLE
#include <vector>    // Cần cho std::vector
#include <memory>

namespace nfcsigner {

class NfcsignerPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  NfcsignerPlugin();

  virtual ~NfcsignerPlugin();
    // Thêm các method public để NfcPdfSigner có thể gọi
    std::vector<uint8_t> TransmitAndGetResponse(SCARDHANDLE hCard, const std::vector<uint8_t>& command, DWORD dwActiveProtocol = SCARD_PROTOCOL_T1);
  // Disallow copy and assign.
  NfcsignerPlugin(const NfcsignerPlugin&) = delete;
  NfcsignerPlugin& operator=(const NfcsignerPlugin&) = delete;
  private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
    // --- Các hàm helper cho PC/SC ---
    void HandleSign(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
    void HandleGetPublicKey(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
    void HandleGetCertificate(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
    void HandleSignPdf(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
    void HandleDecryptData(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
    std::vector<uint8_t> SendChainedDecipher(SCARDHANDLE hCard, const std::vector<uint8_t>& encryptedData, DWORD dwActiveProtocol);
    };
    std::vector<uint8_t> CreateComputeSignatureCommand(const std::vector<uint8_t>& data, int keyIndex);

}  // namespace nfcsigner

#endif  // FLUTTER_PLUGIN_NFCSIGNER_PLUGIN_H_
