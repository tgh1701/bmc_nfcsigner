import 'package:flutter/services.dart';
import 'card_status.dart';

/// Một lớp toàn diện để đóng gói kết quả từ các thao tác với thẻ thông minh.
/// Nó chứa dữ liệu trả về, trạng thái, thông điệp và mã SW1/SW2 gốc.
class ServiceResult<T> {
  /// Dữ liệu trả về nếu thao tác thành công (ví dụ: `Uint8List` cho chữ ký).
  final T? data;

  /// Trạng thái tổng quát của thao tác.
  final CardStatus status;

  /// Một thông điệp mô tả chi tiết về kết quả, dùng để hiển thị cho người dùng hoặc ghi log.
  final String message;

  /// Mã trạng thái SW1 gốc từ phản hồi APDU (nếu có). Rất hữu ích để gỡ lỗi.
  final int? sw1;

  /// Mã trạng thái SW2 gốc từ phản hồi APDU (nếu có). Rất hữu ích để gỡ lỗi.
  final int? sw2;

  /// Getter tiện lợi để kiểm tra thao tác có thành công hay không.
  bool get isSuccess => status == CardStatus.ok;

  /// Constructor cho trường hợp thành công.
  ServiceResult.success(this.data, {this.message = 'Thành công'})
      : status = CardStatus.ok,
        sw1 = 0x90,
        sw2 = 0x00;

  /// Constructor cho trường hợp thất bại.
  ServiceResult.failure({
    required this.status,
    required this.message,
    this.sw1,
    this.sw2,
  }) : data = null;

  /// Factory constructor để tạo một `ServiceResult` từ một `PlatformException`.
  /// Điều này giúp chuyển đổi lỗi từ lớp native sang lớp kết quả một cách nhất quán.
  factory ServiceResult.fromPlatformException(PlatformException e) {
    final status = _mapErrorCodeToStatus(e.code);
    final details = e.details as Map<dynamic, dynamic>?;

    return ServiceResult.failure(
      status: status,
      message: e.message ?? status.description,
      sw1: details?['sw1'] as int?,
      sw2: details?['sw2'] as int?,
    );
  }

  /// Hàm helper để chuyển mã lỗi (String) từ native sang `CardStatus` (enum).
  static CardStatus _mapErrorCodeToStatus(String errorCode) {
    // Logic này có thể được chuyển vào đây từ file API chính để tập trung hóa
    switch (errorCode) {
      case 'AUTH_ERROR':
        return CardStatus.authError;
      case 'COMMUNICATION_ERROR':
        return CardStatus.communicationError;
      case 'TAG_NOT_SUPPORTED':
        return CardStatus.unsupportedCard;
      case 'NFC_UNAVAILABLE':
        return CardStatus.nfcUnavailable;
      case 'APPLET_NOT_SELECTED':
        return CardStatus.appletNotSelected;
      case 'INVALID_PARAMETERS':
        return CardStatus.invalidParameters;
      case 'OPERATION_NOT_SUPPORTED':
        return CardStatus.operationNotSupported;
      default:
        return CardStatus.unknownError;
    }
  }

  @override
  String toString() {
    if (isSuccess) {
      return 'Success(data: $data)';
    } else {
      final swString = (sw1 != null && sw2 != null)
          ? ', SW: ${sw1!.toRadixString(16).padLeft(2, '0')}${sw2!.toRadixString(16).padLeft(2, '0')}'
          : '';
      return 'Failure(status: $status, message: "$message"$swString)';
    }
  }
}