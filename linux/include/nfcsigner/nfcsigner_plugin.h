#pragma once


#ifdef _WIN32
#include <windows.h>
#include <winscard.h>
#else
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#endif

//#include <flutter/method_channel.h>
#include <flutter/plugin_registrar.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <string>
#include <vector>

namespace nfcsigner {

    class NfcsignerPlugin : public flutter::Plugin {
    public:
        static void RegisterWithRegistrar(flutter::PluginRegistrar* registrar);

        NfcsignerPlugin();
        virtual ~NfcsignerPlugin();

        // Disallow copy and assign.
        NfcsignerPlugin(const NfcsignerPlugin&) = delete;
        NfcsignerPlugin& operator=(const NfcsignerPlugin&) = delete;

    private:
        void HandleMethodCall(
                const flutter::MethodCall<flutter::EncodableValue>& method_call,
                std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

        // Helper methods
        std::vector<uint8_t> TransmitAndGetResponse(SCARDHANDLE hCard, const std::vector<uint8_t>& command);
        void HandleSign(const flutter::EncodableMap* args,
                        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
        void HandleGetPublicKey(const flutter::EncodableMap* args,
                                std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
        void HandleGetCertificate(const flutter::EncodableMap* args,
                                  std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
        void HandleSignPdf(const flutter::EncodableMap* args,
                           std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
    };

}  // namespace nfcsig