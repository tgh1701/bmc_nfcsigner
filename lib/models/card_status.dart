/// Enum đại diện cho các trạng thái kết quả chính khi giao tiếp với thẻ thông minh.
/// Các trạng thái này được nhóm lại từ các mã lỗi chi tiết trong `BC_STATUS` của C#.
enum CardStatus {
  /// Thao tác thành công (tương đương SW1/SW2 = 9000).
  ok,

  /// Lỗi chung liên quan đến giao tiếp vật lý với thẻ.
  /// (VD: mất kết nối, timeout, lỗi checksum).
  communicationError,

  /// Lỗi xác thực, thường liên quan đến PIN, PUK hoặc quyền truy cập.
  /// (VD: sai PIN, hết số lần thử, khóa bị khóa).
  authError,

  /// Lỗi xảy ra khi thẻ không hỗ trợ một lệnh hoặc thuật toán được yêu cầu.
  /// (VD: loại khóa không được hỗ trợ, thuật toán không tồn tại).
  operationNotSupported,

  /// Lỗi khi dữ liệu hoặc tham số gửi đến thẻ không hợp lệ.
  /// (VD: độ dài dữ liệu sai, kích thước khóa không đúng).
  invalidParameters,

  /// Lỗi xảy ra khi không thể chọn được Applet trên thẻ.
  /// Thường do AID sai hoặc Applet không tồn tại.
  appletNotSelected,

  /// Thẻ được phát hiện nhưng không tương thích hoặc không được hỗ trợ.
  /// (VD: không phải thẻ ISO 7816, loại thẻ không xác định).
  unsupportedCard,

  /// Không có thẻ nào được phát hiện khi NFC được kích hoạt.
  noCardFound,

  /// Thiết bị không hỗ trợ NFC hoặc NFC đang bị tắt.
  nfcUnavailable,

  /// Một lỗi không xác định đã xảy ra.
  unknownError,
}

/// Extension để cung cấp mô tả thân thiện cho từng trạng thái.
extension CardStatusExtension on CardStatus {
  String get description {
    switch (this) {
      case CardStatus.ok:
        return 'Thao tác thành công';
      case CardStatus.communicationError:
        return 'Lỗi giao tiếp với thẻ';
      case CardStatus.authError:
        return 'Lỗi xác thực (PIN/quyền)';
      case CardStatus.operationNotSupported:
        return 'Thao tác không được hỗ trợ';
      case CardStatus.invalidParameters:
        return 'Tham số không hợp lệ';
      case CardStatus.appletNotSelected:
        return 'Không thể chọn ứng dụng trên thẻ';
      case CardStatus.unsupportedCard:
        return 'Thẻ không được hỗ trợ';
      case CardStatus.noCardFound:
        return 'Không tìm thấy thẻ';
      case CardStatus.nfcUnavailable:
        return 'NFC không có sẵn';
      case CardStatus.unknownError:
        return 'Lỗi không xác định';
      }
  }
}