import 'package:flutter_test/flutter_test.dart';
import 'package:nfcsigner/nfcsigner.dart';
import 'package:nfcsigner/nfcsigner_platform_interface.dart';
import 'package:nfcsigner/nfcsigner_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockNfcsignerPlatform
    with MockPlatformInterfaceMixin
    implements NfcsignerPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final NfcsignerPlatform initialPlatform = NfcsignerPlatform.instance;

  test('$MethodChannelNfcsigner is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelNfcsigner>());
  });

  test('getPlatformVersion', () async {
    Nfcsigner nfcsignerPlugin = Nfcsigner();
    MockNfcsignerPlatform fakePlatform = MockNfcsignerPlatform();
    NfcsignerPlatform.instance = fakePlatform;
  });
}
