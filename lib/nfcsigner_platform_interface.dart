import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'nfcsigner_method_channel.dart';

abstract class NfcsignerPlatform extends PlatformInterface {
  /// Constructs a NfcsignerPlatform.
  NfcsignerPlatform() : super(token: _token);

  static final Object _token = Object();

  static NfcsignerPlatform _instance = MethodChannelNfcsigner();

  /// The default instance of [NfcsignerPlatform] to use.
  ///
  /// Defaults to [MethodChannelNfcsigner].
  static NfcsignerPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [NfcsignerPlatform] when
  /// they register themselves.
  static set instance(NfcsignerPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
