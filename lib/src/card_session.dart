import 'dart:typed_data';

import 'package:flutter/services.dart';

import '../models/card_status.dart';
import '../models/service_result.dart';

/// Kênh riêng cho các lệnh phiên. Cùng tên kênh với [Nfcsigner] — tên kênh là
/// định danh, tạo thêm một thể hiện là hợp lệ và không tốn tài nguyên.
const MethodChannel _channel = MethodChannel('nfcsigner');

/// Một phiên làm việc mở với thẻ: applet đã chọn, PIN đã xác thực.
///
/// Vì sao cần: mỗi lệnh của plugin trước đây đi trọn vòng
/// `connect → SELECT → VERIFY PIN → thao tác → disconnect`. Mở một hộp thư có
/// 20 thư mã hoá nghĩa là 20 lần chạm thẻ NFC và 20 lần nhập PIN. Một phiên
/// cho phép chạm một lần rồi giải mã cả loạt.
///
/// Phiên giữ thẻ ở trạng thái **đã xác thực PIN**, nên nó là tài nguyên nhạy
/// cảm. Luôn đóng bằng [close] khi xong, và đừng giữ mở lâu hơn mức cần thiết.
/// Phía native tự đóng phiên sau một khoảng không hoạt động như một lớp phòng
/// vệ, nhưng đó là lưới an toàn chứ không phải cách quản lý vòng đời.
abstract class CardSession {
  /// Định danh phiên do lớp native cấp.
  String get handle;

  /// Phiên còn dùng được hay không. `false` sau khi [close], hoặc sau khi lớp
  /// native báo phiên đã chết (rút thẻ, hết hạn không hoạt động).
  bool get isOpen;

  /// Phiên này có chạy trên đường native thật hay đang dùng đường lui.
  ///
  /// `false` nghĩa là nền tảng chưa hỗ trợ phiên: mỗi lần giải mã vẫn là một
  /// giao dịch thẻ đầy đủ. Giao diện nên dùng thông tin này để quyết định có
  /// hiển thị lời nhắc "chạm thẻ một lần cho N thư" hay không.
  bool get isNative;

  /// Giải mã một khối dữ liệu.
  ///
  /// [purpose] cho lớp native biết việc này để làm gì, để lời nhắc chạm thẻ
  /// nói đúng tên — ví dụ `'kdsChallenge'` là xác nhận thẻ với máy chủ khoá,
  /// không phải mở thư.
  Future<ServiceResult<Uint8List>> decrypt(Uint8List ciphertext,
      {String? purpose});

  /// Giải mã nhiều khối trong cùng một phiên.
  ///
  /// Trả về danh sách cùng độ dài với đầu vào; phần tử `null` là khối giải mã
  /// thất bại. Thất bại của một khối không huỷ cả loạt — với S-Mail, một thư
  /// không mã hoá cho thẻ này không được phép làm hỏng việc mở những thư khác.
  ///
  /// Ngoại lệ: nếu thẻ báo mất trạng thái bảo mật (SW 6982) hoặc điều kiện sử
  /// dụng không thoả (SW 6985) thì phiên coi như đã chết, phần còn lại của
  /// loạt bị bỏ qua và [isOpen] chuyển thành `false`.
  Future<ServiceResult<List<Uint8List?>>> decryptBatch(
    List<Uint8List> ciphertexts, {
    String? purpose,
  });

  /// Ký một `DigestInfo` bằng khoá ký của thẻ, trong phiên đang mở.
  ///
  /// Thẻ OpenPGP tách PIN thành hai chế độ: 0x81 cho chữ ký và 0x82 cho giải
  /// mã. Phiên xác thực cả hai khi mở, nên gửi và nhận dùng chung một lần nhập
  /// PIN thay vì mỗi việc một lần.
  ///
  /// Một số thẻ đặt PW1 chỉ có hiệu lực cho đúng một lần ký (PW status byte 0
  /// bằng 0x00); lớp native xác thực lại trước mỗi chữ ký khi gặp thẻ như vậy.
  Future<ServiceResult<Uint8List>> sign(Uint8List digestInfo);

  /// Đóng phiên và ngắt kết nối thẻ.
  ///
  /// An toàn khi gọi nhiều lần.
  Future<void> close();
}

/// Phiên chạy trên lớp native: thẻ được giữ kết nối giữa các lệnh.
class _NativeCardSession implements CardSession {
  @override
  final String handle;

  bool _open = true;

  _NativeCardSession(this.handle);

  @override
  bool get isOpen => _open;

  @override
  bool get isNative => true;

  @override
  Future<ServiceResult<Uint8List>> decrypt(Uint8List ciphertext,
      {String? purpose}) async {
    final result = await decryptBatch([ciphertext], purpose: purpose);
    if (!result.isSuccess) {
      return ServiceResult.failure(
        status: result.status,
        message: result.message,
        sw1: result.sw1,
        sw2: result.sw2,
      );
    }
    final first = result.data?.first;
    if (first == null) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: 'Thẻ không giải mã được khối dữ liệu này',
      );
    }
    return ServiceResult.success(first);
  }

  @override
  Future<ServiceResult<List<Uint8List?>>> decryptBatch(
    List<Uint8List> ciphertexts, {
    String? purpose,
  }) async {
    if (!_open) {
      return ServiceResult.failure(
        status: CardStatus.communicationError,
        message: 'Phiên thẻ đã đóng',
      );
    }
    if (ciphertexts.isEmpty) {
      return ServiceResult.success(const <Uint8List?>[]);
    }

    try {
      final raw = await _channel.invokeMethod<List<dynamic>>('decryptBatch', {
        'sessionHandle': handle,
        'ciphertexts': ciphertexts,
        if (purpose != null) 'purpose': purpose,
      });

      if (raw == null) {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Lớp native không trả về kết quả',
        );
      }

      return ServiceResult.success(
        raw.map((e) => e == null ? null : e as Uint8List).toList(),
      );
    } on PlatformException catch (e) {
      // Phiên chết thì đánh dấu ngay để lần gọi sau không đi tiếp vào chỗ hỏng.
      if (e.code == 'SESSION_INVALID' || e.code == 'SESSION_DEAD') {
        _open = false;
      }
      return ServiceResult.fromPlatformException(e);
    }
  }

  @override
  Future<ServiceResult<Uint8List>> sign(Uint8List digestInfo) async {
    if (!_open) {
      return ServiceResult.failure(
        status: CardStatus.communicationError,
        message: 'Phiên thẻ đã đóng',
      );
    }
    try {
      final sig = await _channel.invokeMethod<Uint8List>('signInSession', {
        'sessionHandle': handle,
        'digestInfo': digestInfo,
      });
      if (sig == null || sig.isEmpty) {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Thẻ không trả về chữ ký',
        );
      }
      return ServiceResult.success(sig);
    } on PlatformException catch (e) {
      if (e.code == 'SESSION_INVALID' || e.code == 'SESSION_DEAD') {
        _open = false;
      }
      return ServiceResult.fromPlatformException(e);
    }
  }

  @override
  Future<void> close() async {
    if (!_open) return;
    _open = false;
    try {
      await _channel.invokeMethod<void>('closeSession', {
        'sessionHandle': handle,
      });
    } on PlatformException {
      // Đóng phiên là thao tác dọn dẹp: nếu lớp native đã mất phiên rồi thì
      // trạng thái mong muốn vẫn đạt được.
    }
  }
}

/// Đường lui cho nền tảng chưa hỗ trợ phiên native.
///
/// Giữ nguyên giao diện [CardSession] nhưng mỗi lần giải mã vẫn là một giao
/// dịch thẻ đầy đủ. Nhờ vậy S-Mail viết mã theo phiên ở một chỗ duy nhất mà
/// mọi nền tảng đều chạy được, chỗ nào chưa có phiên thì chỉ chậm hơn.
///
/// Đánh đổi phải biết: đường lui này giữ PIN trong bộ nhớ suốt vòng đời phiên.
/// Dart String là bất biến nên không xoá được — đó là lý do nữa để triển khai
/// phiên native cho mọi nền tảng và bỏ hẳn lớp này.
class _FallbackCardSession implements CardSession {
  @override
  final String handle = 'fallback';

  final String _appletId;
  final String _pin;
  bool _open = true;

  _FallbackCardSession({required String appletId, required String pin})
      : _appletId = appletId,
        _pin = pin;

  @override
  bool get isOpen => _open;

  @override
  bool get isNative => false;

  @override
  Future<ServiceResult<Uint8List>> decrypt(Uint8List ciphertext,
      {String? purpose}) async {
    if (!_open) {
      return ServiceResult.failure(
        status: CardStatus.communicationError,
        message: 'Phiên thẻ đã đóng',
      );
    }
    try {
      final result = await _channel.invokeMethod<Uint8List>('decryptData', {
        'appletID': _appletId,
        'pin': _pin,
        'encryptedData': ciphertext,
        'keyIndex': 0,
        if (purpose != null) 'purpose': purpose,
      });
      if (result == null || result.isEmpty) {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Thẻ trả về dữ liệu rỗng',
        );
      }
      return ServiceResult.success(result);
    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    }
  }

  @override
  Future<ServiceResult<List<Uint8List?>>> decryptBatch(
    List<Uint8List> ciphertexts, {
    String? purpose,
  }) async {
    final out = <Uint8List?>[];
    ServiceResult<Uint8List>? firstFailure;

    for (final ct in ciphertexts) {
      final r = await decrypt(ct, purpose: purpose);
      out.add(r.isSuccess ? r.data : null);
      if (!r.isSuccess) firstFailure ??= r;
      // Mất trạng thái bảo mật thì dừng — phần còn lại cũng sẽ hỏng.
      if (!r.isSuccess && r.status == CardStatus.authError) {
        _open = false;
        break;
      }
    }
    while (out.length < ciphertexts.length) {
      out.add(null);
    }

    // Không mở được khối nào thì đây là lỗi của thẻ, không phải một lô thành
    // công toàn giá trị rỗng.
    //
    // null trong danh sách có nghĩa hẹp: "thẻ này không phải người nhận của
    // khối đó". Ép mọi thất bại thành null rồi báo cả lô là thành công thì
    // lý do thật — sai PIN, chọn applet hỏng, SW thẻ trả về — biến mất hết,
    // và lớp gọi chỉ còn nói được "không giải mã được dữ liệu". Cả lô hỏng
    // thì đó không thể là trùng hợp của từng khối.
    if (firstFailure != null && out.every((e) => e == null)) {
      return ServiceResult.failure(
        status: firstFailure.status,
        message: firstFailure.message,
        sw1: firstFailure.sw1,
        sw2: firstFailure.sw2,
      );
    }

    return ServiceResult.success(out);
  }

  @override
  Future<ServiceResult<Uint8List>> sign(Uint8List digestInfo) async {
    if (!_open) {
      return ServiceResult.failure(
        status: CardStatus.communicationError,
        message: 'Phiên thẻ đã đóng',
      );
    }
    try {
      final sig = await _channel.invokeMethod<Uint8List>('generateSignature', {
        'appletID': _appletId,
        'pin': _pin,
        'dataToSign': digestInfo,
        'keyIndex': 0,
      });
      if (sig == null || sig.isEmpty) {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Thẻ không trả về chữ ký',
        );
      }
      return ServiceResult.success(sig);
    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    }
  }

  @override
  Future<void> close() async {
    _open = false;
  }
}

/// Các thao tác cấp phiên với thẻ.
class CardSessionApi {
  const CardSessionApi._();

  /// Mở một phiên: chọn applet và xác thực PIN một lần.
  ///
  /// Nếu nền tảng chưa hỗ trợ phiên native, trả về một phiên đường lui hoạt
  /// động đúng ngữ nghĩa nhưng mỗi lệnh vẫn là một giao dịch thẻ đầy đủ
  /// ([CardSession.isNative] cho biết đang ở trường hợp nào).
  static Future<ServiceResult<CardSession>> open({
    required String appletID,
    required String pin,
    Duration idleTimeout = const Duration(minutes: 5),
  }) async {
    try {
      final handle = await _channel.invokeMethod<String>('openSession', {
        'appletID': appletID,
        'pin': pin,
        'idleTimeoutMs': idleTimeout.inMilliseconds,
      });

      if (handle == null || handle.isEmpty) {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Lớp native không cấp được định danh phiên',
        );
      }
      return ServiceResult.success(_NativeCardSession(handle));
    } on MissingPluginException {
      // Nền tảng chưa triển khai phiên — dùng đường lui.
      return ServiceResult.success(
        _FallbackCardSession(appletId: appletID, pin: pin),
      );
    } on PlatformException catch (e) {
      if (e.code == 'NOT_IMPLEMENTED') {
        return ServiceResult.success(
          _FallbackCardSession(appletId: appletID, pin: pin),
        );
      }
      return ServiceResult.fromPlatformException(e);
    }
  }

  /// Số lần nhập PIN còn lại trước khi thẻ bị khoá.
  ///
  /// Đọc PW status bytes của thẻ OpenPGP (`GET DATA 00 CA 00 C4`), byte thứ 5
  /// là bộ đếm của PW1. Cần cho giao diện vì [CardStatus.authError] gộp chung
  /// "sai PIN" với "thẻ đã bị khoá", nên nếu không có số này thì không thể
  /// cảnh báo người dùng trước lần thử cuối.
  ///
  /// Trả về [CardStatus.operationNotSupported] nếu nền tảng chưa triển khai.
  static Future<ServiceResult<int>> getPinRetryCounter({
    required String appletID,
  }) async {
    try {
      final value = await _channel.invokeMethod<int>('getPinRetryCounter', {
        'appletID': appletID,
      });
      if (value == null) {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Không đọc được số lần thử còn lại',
        );
      }
      return ServiceResult.success(value);
    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ đọc số lần thử PIN',
      );
    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    }
  }
}
