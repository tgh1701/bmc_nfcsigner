import 'dart:async';

import 'package:flutter/services.dart';

/// Việc đang chờ thẻ để làm.
///
/// Mã chứ không phải câu đã dịch: plugin không quyết định ngôn ngữ, giao diện
/// dịch. Một lời nhắc chung chung buộc người dùng chạm thẻ mà không biết để
/// làm gì — và một lời nhắc nói sai việc còn tệ hơn, vì họ tưởng ứng dụng đang
/// làm chuyện khác.
enum CardTask {
  readSigningKey,
  readDecryptionKey,
  readKey,
  readCertificate,
  sign,
  decrypt,

  /// Giải thách thức của máy chủ khoá để chứng minh người dùng giữ thẻ.
  verifyCard,
  signPdf,
  signXml,
  unknown,
}

/// Trạng thái của việc chờ người dùng đưa thẻ vào.
enum CardPromptState {
  /// Đầu đọc đã bật và đang chờ thẻ. Đây là lúc phải nhắc người dùng.
  waiting,

  /// Đã bắt được thẻ, đang trao đổi dữ liệu. Người dùng phải giữ nguyên thẻ.
  reading,

  /// Xong (thành công, lỗi, hoặc bị huỷ). Gỡ lời nhắc đi.
  done,
}

/// Lời nhắc chạm thẻ cho những nền tảng không tự hiện.
///
/// iOS dựng `NFCTagReaderSession`, và hệ điều hành hiện sẵn một sheet với dòng
/// chữ hướng dẫn — người dùng luôn biết phải làm gì. Android thì
/// `NfcAdapter.enableReaderMode()` **không hiện bất cứ thứ gì**: đầu đọc bật
/// lên và chờ trong im lặng. Người dùng chỉ thấy ứng dụng đứng yên rồi báo lỗi
/// hết giờ, mà không hề biết là nó đang đợi mình chạm thẻ.
///
/// Nên trên Android, giao diện phải tự dựng lời nhắc — và nó cần biết chính
/// xác lúc nào đầu đọc đang chờ. Chỉ lớp native biết điều đó, nên nó phát ra
/// đây thay vì để phía Dart đoán quanh mỗi lời gọi.
///
/// Nền tảng nào tự hiện lời nhắc (iOS) hoặc không cần (thẻ cắm cố định trên
/// máy bàn) thì không phát gì cả, và [events] im lặng — phía gọi không cần
/// phân biệt nền tảng.
class CardPrompt {
  const CardPrompt._();

  static const EventChannel _channel =
      EventChannel('nfcsigner/card_prompt');
  static const MethodChannel _methods = MethodChannel('nfcsigner');

  static Stream<CardPromptEvent>? _events;

  /// Dòng trạng thái chờ thẻ. Chỉ phát trên nền tảng không có lời nhắc sẵn.
  static Stream<CardPromptEvent> get events {
    return _events ??= _channel
        .receiveBroadcastStream()
        .map(_parse)
        .where((e) => e != null)
        .cast<CardPromptEvent>()
        .asBroadcastStream();
  }

  static CardPromptEvent? _parse(dynamic event) {
    if (event is! Map) return null;
    final state = switch (event['state']) {
      'waiting' => CardPromptState.waiting,
      'reading' => CardPromptState.reading,
      'done' => CardPromptState.done,
      _ => null,
    };
    if (state == null) return null;

    final task = switch (event['task']) {
      'readSigningKey' => CardTask.readSigningKey,
      'readDecryptionKey' => CardTask.readDecryptionKey,
      'readKey' => CardTask.readKey,
      'readCertificate' => CardTask.readCertificate,
      'sign' => CardTask.sign,
      'decrypt' => CardTask.decrypt,
      'verifyCard' => CardTask.verifyCard,
      'signPdf' => CardTask.signPdf,
      'signXml' => CardTask.signXml,
      _ => CardTask.unknown,
    };
    return CardPromptEvent(state: state, task: task);
  }

  /// Huỷ việc chờ thẻ đang diễn ra.
  ///
  /// Cần thiết vì lời nhắc do ứng dụng tự dựng: đóng nó đi mà không tắt đầu
  /// đọc thì thao tác vẫn sống ngầm và Future phía gọi treo vô hạn.
  static Future<void> cancel() async {
    try {
      await _methods.invokeMethod<void>('cancelNfcWait');
    } on PlatformException {
      // Nền tảng không có gì để huỷ — không phải lỗi.
    } on MissingPluginException {
      // Nền tảng chưa triển khai — cũng không phải lỗi.
    }
  }
}

/// Một lần cập nhật trạng thái chờ thẻ.
class CardPromptEvent {
  const CardPromptEvent({required this.state, required this.task});

  final CardPromptState state;
  final CardTask task;
}
