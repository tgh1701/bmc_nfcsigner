package com.bmc.nfcsigner.usb

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.*
import android.os.Build
import androidx.core.content.ContextCompat
import com.bmc.nfcsigner.core.DebugLogger

class UsbDeviceManager(private val context: Context) {
    private val logger = DebugLogger("UsbDeviceManager")
    private val usbManager: UsbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager

    private var usbDevice: UsbDevice? = null
    private var usbConnection: UsbDeviceConnection? = null
    private var usbInterface: UsbInterface? = null
    private var endpointIn: UsbEndpoint? = null
    private var endpointOut: UsbEndpoint? = null
    private var permissionCallback: ((Boolean) -> Unit)? = null
    private val usbPermissionAction = "com.bmc.nfcsigner.USB_PERMISSION"

    // Track which device the current connection was opened for
    private var connectedDeviceName: String? = null

    // Track additionally claimed interfaces (for composite device isolation)
    private val claimedInterfaces = mutableListOf<UsbInterface>()

    // CCID descriptor parameters — read from USB descriptors
    var ccidMaxMessageLength: Int = 65544  // Default: CCID spec max
        private set
    var ccidExchangeLevel: Int = 0x00020000  // Default: Short APDU
        private set
    var ccidDwFeatures: Int = 0
        private set

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                usbPermissionAction -> {
                    synchronized(this) {
                        val device: UsbDevice? =
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                        val granted =
                            intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                        if (granted && device != null) {
                            usbDevice = device
                            permissionCallback?.invoke(true)
                        } else {
                            logger.debug("USB permission denied or device not found")
                            permissionCallback?.invoke(false)
                        }
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val device: UsbDevice? =
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    logger.debug("USB device detached: ${device?.deviceName}")
                    // Release stale connection when device is physically unplugged
                    forceRelease()
                    usbDevice = null
                    logger.debug("USB resources released after detach")
                }
            }
        }
    }

    init {
        try {
            val filter = IntentFilter(usbPermissionAction)
            filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                // Android 13+ requires RECEIVER_NOT_EXPORTED flag
                ContextCompat.registerReceiver(
                    context, usbReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED
                )
            } else {
                context.registerReceiver(usbReceiver, filter)
            }
            logger.debug("USB permission receiver registered (with detach listener)")
        } catch (e: Exception) {
            logger.debug("Failed to register USB receiver: ${e.message}")
        }
    }

    fun isSmartCardReaderConnected(): Boolean {
        val deviceList = usbManager.deviceList
        logger.debug("USB device scan: ${deviceList.size} device(s) found")
        for (device in deviceList.values) {
            logger.debug("  Device: ${device.deviceName} VID=0x${device.vendorId.toString(16)} PID=0x${device.productId.toString(16)} interfaces=${device.interfaceCount}")
            for (i in 0 until device.interfaceCount) {
                val intf = device.getInterface(i)
                logger.debug("    Interface $i: class=0x${intf.interfaceClass.toString(16)} subclass=0x${intf.interfaceSubclass.toString(16)} protocol=0x${intf.interfaceProtocol.toString(16)}")
            }
            if (isSmartCardReader(device)) {
                logger.debug("  → Smart Card reader detected!")
                usbDevice = device
                return true
            }
        }
        if (deviceList.isEmpty()) {
            logger.debug("No USB devices found. Possible causes: USB OTG not supported, no permission, or device not enumerated yet")
        }
        return false
    }

    private fun isSmartCardReader(device: UsbDevice): Boolean {
        for (i in 0 until device.interfaceCount) {
            val usbInterface = device.getInterface(i)
            if (usbInterface.interfaceClass == 0x0B) { // Smart Card class (CCID)
                return true
            }
        }
        return false
    }

    fun hasPermission(): Boolean {
        return usbDevice?.let { usbManager.hasPermission(it) } ?: false
    }

    fun requestPermission(callback: (Boolean) -> Unit) {
        val device = usbDevice ?: return callback(false)
        permissionCallback = callback
        val permissionIntent = PendingIntent.getBroadcast(
            context, 0, Intent(usbPermissionAction), PendingIntent.FLAG_IMMUTABLE
        )
        usbManager.requestPermission(device, permissionIntent)
    }

    /**
     * Kết nối đến USB device.
     * Nếu đã có connection sẵn (từ lần trước), tái sử dụng để tránh
     * kernel driver re-attach trên composite device.
     */
    fun connect(): Boolean {
        val device = usbDevice ?: return false

        try {
            if (!usbManager.hasPermission(device)) {
                logger.debug("No USB permission")
                return false
            }

            // Nếu đã có connection hợp lệ, tái sử dụng
            if (usbConnection != null && usbInterface != null &&
                endpointIn != null && endpointOut != null) {

                // Kiểm tra connection còn hoạt động và cùng device không
                if (connectedDeviceName == device.deviceName && usbManager.hasPermission(device)) {
                    logger.debug("Reusing existing USB connection for ${device.deviceName}")
                    return true
                } else {
                    // Connection cũ không hợp lệ hoặc device khác → cleanup và connect lại
                    logger.debug("Existing connection stale (connected=${connectedDeviceName}, current=${device.deviceName}), reconnecting...")
                    forceRelease()
                }
            }

            logger.debug("Connecting to device: ${device.deviceName}, VID=0x${device.vendorId.toString(16)}, PID=0x${device.productId.toString(16)}")
            logger.debug("Device has ${device.interfaceCount} interface(s)")

            usbConnection = usbManager.openDevice(device) ?: run {
                logger.debug("Failed to open USB device")
                return false
            }

            // Enumerate all interfaces for debugging composite devices
            for (i in 0 until device.interfaceCount) {
                val usbIntf = device.getInterface(i)
                logger.debug("  Interface $i: class=0x${usbIntf.interfaceClass.toString(16)}, " +
                        "subclass=0x${usbIntf.interfaceSubclass.toString(16)}, " +
                        "protocol=0x${usbIntf.interfaceProtocol.toString(16)}, " +
                        "endpoints=${usbIntf.endpointCount}")
            }

            // Find CCID interface (class 0x0B = Smart Card)
            for (i in 0 until device.interfaceCount) {
                val usbIntf = device.getInterface(i)
                if (usbIntf.interfaceClass == 0x0B ||
                    (usbIntf.interfaceClass == 0xFF && usbIntf.interfaceProtocol == 0)) {
                    usbInterface = usbIntf
                    logger.debug("  → Selected CCID interface $i (class=0x${usbIntf.interfaceClass.toString(16)})")
                    break
                }
            }

            if (usbInterface == null) {
                logger.debug("No CCID interface found, falling back to interface 0")
                usbInterface = device.getInterface(0)
            }

            if (!usbConnection!!.claimInterface(usbInterface, true)) {
                logger.debug("Failed to claim USB interface ${usbInterface!!.id}")
                return false
            }
            logger.debug("Claimed interface ${usbInterface!!.id}")

            // QUAN TRỌNG: Trên composite device, kernel driver của các interface khác
            // (đặc biệt MSC - Mass Storage) có thể giao tiếp với cùng chip vật lý,
            // gây reset trạng thái card giữa các APDU command (ví dụ GET RESPONSE trả rỗng).
            // Claim tất cả interface với force=true để detach kernel driver của chúng.
            if (device.interfaceCount > 1) {
                for (i in 0 until device.interfaceCount) {
                    val otherIntf = device.getInterface(i)
                    if (otherIntf != usbInterface) {
                        try {
                            if (usbConnection!!.claimInterface(otherIntf, true)) {
                                claimedInterfaces.add(otherIntf)
                                logger.debug("  Claimed interface $i (class=0x${otherIntf.interfaceClass.toString(16)}) to prevent driver interference")
                            }
                        } catch (e: Exception) {
                            logger.debug("  Could not claim interface $i: ${e.message}")
                        }
                    }
                }
            }

            // Find Bulk IN and Bulk OUT endpoints
            for (i in 0 until usbInterface!!.endpointCount) {
                val endpoint = usbInterface!!.getEndpoint(i)
                logger.debug("  Endpoint $i: address=0x${endpoint.address.toString(16)}, " +
                        "direction=${if (endpoint.direction == UsbConstants.USB_DIR_IN) "IN" else "OUT"}, " +
                        "type=${when(endpoint.type) { UsbConstants.USB_ENDPOINT_XFER_BULK -> "BULK"; UsbConstants.USB_ENDPOINT_XFER_INT -> "INT"; else -> "OTHER" }}, " +
                        "maxPacket=${endpoint.maxPacketSize}")
                when {
                    endpoint.direction == UsbConstants.USB_DIR_IN &&
                            endpoint.type == UsbConstants.USB_ENDPOINT_XFER_BULK -> {
                        endpointIn = endpoint
                        logger.debug("  → Selected as Bulk IN endpoint")
                    }
                    endpoint.direction == UsbConstants.USB_DIR_OUT &&
                            endpoint.type == UsbConstants.USB_ENDPOINT_XFER_BULK -> {
                        endpointOut = endpoint
                        logger.debug("  → Selected as Bulk OUT endpoint")
                    }
                }
            }

            if (endpointIn == null || endpointOut == null) {
                logger.debug("Failed to find Bulk endpoints (IN=${endpointIn != null}, OUT=${endpointOut != null})")
                return false
            }

            logger.debug("Successfully connected to USB reader")

            // Track which device this connection belongs to
            connectedDeviceName = device.deviceName

            // Đọc CCID descriptor để xác định exchange level và max message length
            readCcidDescriptor()

            return true

        } catch (e: Exception) {
            logger.debug("USB connection error: ${e.message}")
            return false
        }
    }

    /**
     * Đọc và parse CCID class descriptor từ raw USB descriptors.
     * Log dwFeatures (exchange level) và dwMaxCCIDMessageLength.
     */
    private fun readCcidDescriptor() {
        try {
            val rawDescriptors = usbConnection?.rawDescriptors ?: run {
                logger.debug("Cannot read raw USB descriptors")
                return
            }

            var i = 0
            var inCcidInterface = false

            while (i < rawDescriptors.size - 1) {
                val bLength = rawDescriptors[i].toInt() and 0xFF
                val bDescriptorType = rawDescriptors[i + 1].toInt() and 0xFF

                if (bLength == 0) break
                if (i + bLength > rawDescriptors.size) break

                // Interface descriptor (type = 0x04)
                if (bDescriptorType == 0x04 && bLength >= 9) {
                    val interfaceClass = rawDescriptors[i + 5].toInt() and 0xFF
                    inCcidInterface = (interfaceClass == 0x0B)
                }

                // CCID class descriptor (type = 0x21) within CCID interface
                if (inCcidInterface && bDescriptorType == 0x21 && bLength >= 48) {
                    val dwFeatures = (rawDescriptors[i + 40].toInt() and 0xFF) or
                            ((rawDescriptors[i + 41].toInt() and 0xFF) shl 8) or
                            ((rawDescriptors[i + 42].toInt() and 0xFF) shl 16) or
                            ((rawDescriptors[i + 43].toInt() and 0xFF) shl 24)

                    val dwMaxMsgLen = (rawDescriptors[i + 44].toInt() and 0xFF) or
                            ((rawDescriptors[i + 45].toInt() and 0xFF) shl 8) or
                            ((rawDescriptors[i + 46].toInt() and 0xFF) shl 16) or
                            ((rawDescriptors[i + 47].toInt() and 0xFF) shl 24)

                    val exchangeLevel = when {
                        dwFeatures and 0x00040000 != 0 -> "Extended APDU"
                        dwFeatures and 0x00020000 != 0 -> "Short APDU"
                        dwFeatures and 0x00010000 != 0 -> "TPDU"
                        else -> "Character"
                    }

                    logger.debug("CCID Descriptor:")
                    logger.debug("  dwFeatures: 0x${dwFeatures.toString(16).padStart(8, '0')}")
                    logger.debug("  Exchange level: $exchangeLevel")
                    logger.debug("  dwMaxCCIDMessageLength: $dwMaxMsgLen bytes")

                    // Store for use by UsbTransceiver
                    ccidDwFeatures = dwFeatures
                    ccidMaxMessageLength = dwMaxMsgLen
                    ccidExchangeLevel = when {
                        dwFeatures and 0x00040000 != 0 -> 0x00040000  // Extended APDU
                        dwFeatures and 0x00020000 != 0 -> 0x00020000  // Short APDU
                        dwFeatures and 0x00010000 != 0 -> 0x00010000  // TPDU
                        else -> 0  // Character
                    }

                    return
                }

                i += bLength
            }

            logger.debug("CCID descriptor not found in raw USB descriptors")
        } catch (e: Exception) {
            logger.debug("Error reading CCID descriptor: ${e.message}")
        }
    }

    fun createTransceiver(): UsbTransceiver? {
        return try {
            logger.debug("Creating UsbTransceiver:")
            logger.debug("  endpointIn maxPacketSize: ${endpointIn!!.maxPacketSize}")
            logger.debug("  endpointOut maxPacketSize: ${endpointOut!!.maxPacketSize}")
            logger.debug("  ccidMaxMessageLength: $ccidMaxMessageLength")
            logger.debug("  ccidExchangeLevel: 0x${ccidExchangeLevel.toString(16)}")
            logger.debug("  isCompositeDevice: ${usbDevice!!.interfaceCount > 1}")
            UsbTransceiver(
                usbManager,
                usbDevice!!,
                usbConnection!!,
                usbInterface!!,
                endpointIn!!,
                endpointOut!!,
                ccidMaxMessageLength
            )
        } catch (e: Exception) {
            logger.debug("Failed to create USB transceiver: ${e.message}")
            null
        }
    }

    /**
     * Kết thúc session CCID nhưng GIỮ USB connection và interface claims.
     * Trên composite device, nếu release interface thì kernel driver sẽ
     * re-attach ngay lập tức và corrupt card state cho lần connect tiếp theo.
     */
    fun disconnect() {
        // KHÔNG release interface hay close connection ở đây!
        // Giữ connection alive để tránh kernel driver re-attach.
        // Full release chỉ xảy ra trong cleanup().
        logger.debug("USB session ended (connection kept alive)")
    }

    /**
     * Release toàn bộ USB resources. Gọi khi plugin detach hoặc device disconnect.
     */
    private fun forceRelease() {
        try {
            for (intf in claimedInterfaces) {
                try {
                    usbConnection?.releaseInterface(intf)
                } catch (_: Exception) {}
            }
            claimedInterfaces.clear()

            usbInterface?.let { usbConnection?.releaseInterface(it) }
            usbConnection?.close()
        } catch (e: Exception) {
            logger.debug("Error in forceRelease: ${e.message}")
        }

        usbConnection = null
        usbInterface = null
        endpointIn = null
        endpointOut = null
        connectedDeviceName = null
    }

    fun cleanup() {
        forceRelease()
        try {
            context.unregisterReceiver(usbReceiver)
        } catch (e: Exception) {
            // Receiver might not be registered
        }
    }
}