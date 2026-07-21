import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'nfcsigner_platform_interface.dart';

/// An implementation of [NfcsignerPlatform] that uses method channels.
class MethodChannelNfcsigner extends NfcsignerPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('nfcsigner');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
