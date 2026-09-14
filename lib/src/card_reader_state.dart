import 'dart:async';

import 'package:flutter/services.dart';

/// Đầu đọc thẻ cắm cố định (USB/CCID) có đang gắn vào máy hay không.
///
/// Trên máy bàn thẻ nằm trong đầu đọc suốt phiên làm việc, nên giao diện coi
/// "thẻ đang dùng" là một khái niệm có thật và tự đọc thẻ khi cần. Trên di
/// động thì không chắc: cùng một máy có thể đang cắm thẻ qua OTG, hoặc không
/// cắm gì và chỉ dùng NFC. Hai trường hợp đó đòi hai cách cư xử khác hẳn nhau
/// — tự đọc thẻ khi có đầu đọc, và không bao giờ tự đọc khi chỉ có NFC, vì
/// mỗi lần đọc là một lần bắt người dùng chạm thẻ.
///
/// Nền tảng nào chưa triển khai thì [attached] trả `false` và [changes] im
/// lặng, nên phía gọi không cần rẽ nhánh theo nền tảng.
class CardReaderState {
  const CardReaderState._();

  static const MethodChannel _methods = MethodChannel('nfcsigner');
  static const EventChannel _channel = EventChannel('nfcsigner/reader_state');

  static Stream<bool>? _changes;

  /// Có đầu đọc thẻ cắm vào máy ngay lúc này không.
  static Future<bool> get attached async {
    try {
      return await _methods.invokeMethod<bool>('isCardReaderAttached') ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  /// Dòng trạng thái cắm/rút đầu đọc.
  ///
  /// Phát ngay trạng thái hiện tại khi bắt đầu nghe, nên phía nghe không phải
  /// hỏi riêng một lần rồi mới nghe tiếp.
  static Stream<bool> get changes {
    return _changes ??= _channel
        .receiveBroadcastStream()
        .map((e) => e is Map && e['attached'] == true)
        .asBroadcastStream();
  }
}
