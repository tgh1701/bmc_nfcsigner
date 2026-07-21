#include "include/nfcsigner/nfcsigner_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "nfcsigner_plugin.h"

void NfcsignerPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  nfcsigner::NfcsignerPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
