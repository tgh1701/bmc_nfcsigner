#include "include/nfcsigner/nfcsigner_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>

// Macro cho plugin registration
G_DEFINE_TYPE(NfcsignerPlugin, nfcsigner_plugin, g_object_get_type())

#define NFCSIGNER_PLUGIN(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), nfcsigner_plugin_get_type(), \
                              NfcsignerPlugin))

struct _NfcsignerPlugin {
    GObject parent_instance;
};

static void nfcsigner_plugin_dispose(GObject* object) {
    G_OBJECT_CLASS(nfcsigner_plugin_parent_class)->dispose(object);
}

static void nfcsigner_plugin_class_init(NfcsignerPluginClass* klass) {
    G_OBJECT_CLASS(klass)->dispose = nfcsigner_plugin_dispose;
}

static void nfcsigner_plugin_init(NfcsignerPlugin* self) {}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
    NfcsignerPlugin* plugin = NFCSIGNER_PLUGIN(user_data);
    nfcsigner::NfcsignerPlugin::HandleMethodCall(
            flutter::MethodCall<flutter::EncodableValue>(
                    method_call),
            std::make_unique<flutter::MethodResult<flutter::EncodableValue>>(
                    method_call));
}

void nfcsigner_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
    NfcsignerPlugin* plugin = NFCSIGNER_PLUGIN(
            g_object_new(nfcsigner_plugin_get_type(), nullptr));

    g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
    g_autoptr(FlMethodChannel) channel =
                                       fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                                                             "nfcsigner",
                                                             FL_METHOD_CODEC(codec));
    fl_method_channel_set_method_call_handler(channel, method_call_cb,
                                              g_object_ref(plugin),
                                              g_object_unref);

    g_object_unref(plugin);
}