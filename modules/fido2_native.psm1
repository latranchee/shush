# fido2_native.psm1
# CTAP2-over-USB-HID transport for the FIDO2 unlock factor.
#
# Windows has no FIDO2 API that exposes the hmac-secret extension, and
# libfido2 would mean shipping native binaries, so this speaks CTAP2 to the
# token directly. Scope is deliberately narrow: enumerate FIDO HID devices,
# run authenticatorGetInfo / clientPIN / makeCredential / getAssertion, and
# nothing else.
#
# The C# lives here rather than in PowerShell because the protocol is dense
# byte work - 64-byte HID frames, CBOR, big-endian lengths - where a typed
# language removes a whole class of mistakes.
#
# References: CTAP 2.1 (client-to-authenticator protocol), sections on the
# USB HID transport, PIN/UV auth protocol one, and the hmac-secret extension.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Windows PowerShell 5.1 needs System.Core/System.Security named explicitly to
# reach CngKey and ECDiffieHellmanCng. On PowerShell 7 the same parameter
# REPLACES the default .NET reference set instead of adding to it, which drops
# System.Collections and fails the compile, so 7 gets Add-Type's defaults.
$script:addTypeReferences = if ($PSVersionTable.PSEdition -eq 'Core') {
    @{}
} else {
    @{ ReferencedAssemblies = @('System.Security', 'System.Core') }
}

function initialize_fido2_native {
    if ('Shush.Fido2.Ctap2Device' -as [type]) { return }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Shush.Fido2 {

    public class Ctap2Exception : Exception {
        public byte StatusCode { get; private set; }
        public Ctap2Exception(string message) : base(message) { StatusCode = 0; }
        public Ctap2Exception(string message, byte status) : base(message) { StatusCode = status; }
    }

    // ---------- CBOR ----------
    // Only the subset CTAP2 uses. Maps are emitted with keys already in
    // canonical order by the caller, which is why there is no sort here.
    public static class Cbor {
        public static void WriteHead(MemoryStream s, int majorType, ulong value) {
            int mt = majorType << 5;
            if (value < 24) {
                s.WriteByte((byte)(mt | (int)value));
            } else if (value <= 0xFF) {
                s.WriteByte((byte)(mt | 24)); s.WriteByte((byte)value);
            } else if (value <= 0xFFFF) {
                s.WriteByte((byte)(mt | 25));
                s.WriteByte((byte)(value >> 8)); s.WriteByte((byte)value);
            } else if (value <= 0xFFFFFFFF) {
                s.WriteByte((byte)(mt | 26));
                s.WriteByte((byte)(value >> 24)); s.WriteByte((byte)(value >> 16));
                s.WriteByte((byte)(value >> 8)); s.WriteByte((byte)value);
            } else {
                s.WriteByte((byte)(mt | 27));
                for (int i = 7; i >= 0; i--) { s.WriteByte((byte)(value >> (i * 8))); }
            }
        }

        public static void WriteUInt(MemoryStream s, ulong v) { WriteHead(s, 0, v); }
        public static void WriteNegInt(MemoryStream s, long v) { WriteHead(s, 1, (ulong)(-1 - v)); }
        public static void WriteInt(MemoryStream s, long v) {
            if (v >= 0) { WriteUInt(s, (ulong)v); } else { WriteNegInt(s, v); }
        }
        public static void WriteBytes(MemoryStream s, byte[] b) {
            WriteHead(s, 2, (ulong)b.Length); s.Write(b, 0, b.Length);
        }
        public static void WriteText(MemoryStream s, string t) {
            byte[] b = Encoding.UTF8.GetBytes(t);
            WriteHead(s, 3, (ulong)b.Length); s.Write(b, 0, b.Length);
        }
        public static void WriteArrayHead(MemoryStream s, int count) { WriteHead(s, 4, (ulong)count); }
        public static void WriteMapHead(MemoryStream s, int count) { WriteHead(s, 5, (ulong)count); }
        public static void WriteBool(MemoryStream s, bool v) { s.WriteByte((byte)(v ? 0xF5 : 0xF4)); }

        public static object Decode(byte[] data, ref int offset) {
            if (offset >= data.Length) { throw new Ctap2Exception("CBOR ended early"); }
            byte initial = data[offset++];
            int majorType = initial >> 5;
            int additional = initial & 0x1F;
            ulong length = 0;

            if (additional < 24) {
                length = (ulong)additional;
            } else if (additional == 24) {
                length = data[offset++];
            } else if (additional == 25) {
                length = (ulong)((data[offset] << 8) | data[offset + 1]); offset += 2;
            } else if (additional == 26) {
                length = ((ulong)data[offset] << 24) | ((ulong)data[offset + 1] << 16) |
                         ((ulong)data[offset + 2] << 8) | data[offset + 3];
                offset += 4;
            } else if (additional == 27) {
                for (int i = 0; i < 8; i++) { length = (length << 8) | data[offset + i]; }
                offset += 8;
            } else if (additional != 31) {
                throw new Ctap2Exception("Unsupported CBOR additional info " + additional);
            }

            switch (majorType) {
                case 0: return (long)length;
                case 1: return -1L - (long)length;
                case 2: {
                    byte[] bytes = new byte[length];
                    Array.Copy(data, offset, bytes, 0, (int)length);
                    offset += (int)length;
                    return bytes;
                }
                case 3: {
                    string text = Encoding.UTF8.GetString(data, offset, (int)length);
                    offset += (int)length;
                    return text;
                }
                case 4: {
                    List<object> list = new List<object>();
                    for (ulong i = 0; i < length; i++) { list.Add(Decode(data, ref offset)); }
                    return list;
                }
                case 5: {
                    Dictionary<object, object> map = new Dictionary<object, object>();
                    for (ulong i = 0; i < length; i++) {
                        object key = Decode(data, ref offset);
                        object value = Decode(data, ref offset);
                        map[key] = value;
                    }
                    return map;
                }
                case 7:
                    if (additional == 20) { return false; }
                    if (additional == 21) { return true; }
                    if (additional == 22) { return null; }
                    throw new Ctap2Exception("Unsupported CBOR simple value " + additional);
                default:
                    throw new Ctap2Exception("Unsupported CBOR major type " + majorType);
            }
        }
    }

    // ---------- HID enumeration ----------
    internal static class Native {
        internal const int DIGCF_PRESENT = 0x02;
        internal const int DIGCF_DEVICEINTERFACE = 0x10;
        internal const uint GENERIC_READ = 0x80000000;
        internal const uint GENERIC_WRITE = 0x40000000;
        internal const uint FILE_SHARE_READ = 1;
        internal const uint FILE_SHARE_WRITE = 2;
        internal const uint OPEN_EXISTING = 3;

        [StructLayout(LayoutKind.Sequential)]
        internal struct SP_DEVICE_INTERFACE_DATA {
            public int cbSize;
            public Guid InterfaceClassGuid;
            public int Flags;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct HIDD_ATTRIBUTES {
            public int Size;
            public ushort VendorID;
            public ushort ProductID;
            public ushort VersionNumber;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct HIDP_CAPS {
            public ushort Usage;
            public ushort UsagePage;
            public ushort InputReportByteLength;
            public ushort OutputReportByteLength;
            public ushort FeatureReportByteLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)]
            public ushort[] Reserved;
            public ushort NumberLinkCollectionNodes;
            public ushort NumberInputButtonCaps;
            public ushort NumberInputValueCaps;
            public ushort NumberInputDataIndices;
            public ushort NumberOutputButtonCaps;
            public ushort NumberOutputValueCaps;
            public ushort NumberOutputDataIndices;
            public ushort NumberFeatureButtonCaps;
            public ushort NumberFeatureValueCaps;
            public ushort NumberFeatureDataIndices;
        }

        [DllImport("hid.dll")] internal static extern void HidD_GetHidGuid(out Guid guid);
        [DllImport("hid.dll")] internal static extern bool HidD_GetAttributes(IntPtr handle, ref HIDD_ATTRIBUTES attributes);
        [DllImport("hid.dll")] internal static extern bool HidD_GetPreparsedData(IntPtr handle, out IntPtr preparsed);
        [DllImport("hid.dll")] internal static extern bool HidD_FreePreparsedData(IntPtr preparsed);
        [DllImport("hid.dll")] internal static extern int HidP_GetCaps(IntPtr preparsed, ref HIDP_CAPS caps);
        [DllImport("hid.dll", CharSet = CharSet.Unicode)]
        internal static extern bool HidD_GetProductString(IntPtr handle, byte[] buffer, int bufferLength);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, int flags);
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool SetupDiEnumDeviceInterfaces(IntPtr deviceInfoSet, IntPtr deviceInfoData,
            ref Guid interfaceClassGuid, int memberIndex, ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData);
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr deviceInfoSet,
            ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData, IntPtr deviceInterfaceDetailData,
            int deviceInterfaceDetailDataSize, ref int requiredSize, IntPtr deviceInfoData);
        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode,
            IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);
    }

    public class Fido2DeviceInfo {
        public string Path { get; set; }
        public string Product { get; set; }
        public ushort VendorId { get; set; }
        public ushort ProductId { get; set; }
        public int ReportLength { get; set; }
    }

    public static class HidEnumerator {
        // FIDO devices declare usage page 0xF1D0, usage 0x01. That pair is
        // the only reliable discriminator - matching on vendor id would miss
        // every non-Yubico key.
        private const ushort FidoUsagePage = 0xF1D0;
        private const ushort FidoUsage = 0x01;

        public static List<Fido2DeviceInfo> Enumerate() {
            List<Fido2DeviceInfo> found = new List<Fido2DeviceInfo>();
            Guid hidGuid;
            Native.HidD_GetHidGuid(out hidGuid);

            IntPtr deviceInfoSet = Native.SetupDiGetClassDevs(ref hidGuid, IntPtr.Zero, IntPtr.Zero,
                Native.DIGCF_PRESENT | Native.DIGCF_DEVICEINTERFACE);
            if (deviceInfoSet == IntPtr.Zero || deviceInfoSet == new IntPtr(-1)) { return found; }

            try {
                Native.SP_DEVICE_INTERFACE_DATA interfaceData = new Native.SP_DEVICE_INTERFACE_DATA();
                interfaceData.cbSize = Marshal.SizeOf(typeof(Native.SP_DEVICE_INTERFACE_DATA));

                for (int index = 0; ; index++) {
                    if (!Native.SetupDiEnumDeviceInterfaces(deviceInfoSet, IntPtr.Zero, ref hidGuid, index, ref interfaceData)) {
                        break;
                    }

                    int requiredSize = 0;
                    Native.SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref interfaceData, IntPtr.Zero, 0, ref requiredSize, IntPtr.Zero);
                    if (requiredSize <= 0) { continue; }

                    IntPtr detail = Marshal.AllocHGlobal(requiredSize);
                    try {
                        // cbSize is the size of the fixed header, not the
                        // buffer: 8 on 64-bit (alignment), 6 on 32-bit.
                        Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
                        if (!Native.SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref interfaceData, detail, requiredSize, ref requiredSize, IntPtr.Zero)) {
                            continue;
                        }
                        string path = Marshal.PtrToStringUni(new IntPtr(detail.ToInt64() + 4));
                        if (string.IsNullOrEmpty(path)) { continue; }

                        Fido2DeviceInfo info = Probe(path);
                        if (info != null) { found.Add(info); }
                    } finally {
                        Marshal.FreeHGlobal(detail);
                    }
                }
            } finally {
                Native.SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }
            return found;
        }

        private static Fido2DeviceInfo Probe(string path) {
            IntPtr handle = Native.CreateFile(path, Native.GENERIC_READ | Native.GENERIC_WRITE,
                Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero, Native.OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1)) { return null; }

            IntPtr preparsed = IntPtr.Zero;
            try {
                if (!Native.HidD_GetPreparsedData(handle, out preparsed)) { return null; }
                Native.HIDP_CAPS caps = new Native.HIDP_CAPS();
                caps.Reserved = new ushort[17];
                if (Native.HidP_GetCaps(preparsed, ref caps) != 0x00110000) { return null; }
                if (caps.UsagePage != FidoUsagePage || caps.Usage != FidoUsage) { return null; }

                Native.HIDD_ATTRIBUTES attributes = new Native.HIDD_ATTRIBUTES();
                attributes.Size = Marshal.SizeOf(typeof(Native.HIDD_ATTRIBUTES));
                Native.HidD_GetAttributes(handle, ref attributes);

                string product = "";
                byte[] buffer = new byte[256];
                if (Native.HidD_GetProductString(handle, buffer, buffer.Length)) {
                    product = Encoding.Unicode.GetString(buffer).TrimEnd('\0');
                }

                return new Fido2DeviceInfo {
                    Path = path,
                    Product = product,
                    VendorId = attributes.VendorID,
                    ProductId = attributes.ProductID,
                    ReportLength = caps.OutputReportByteLength
                };
            } finally {
                if (preparsed != IntPtr.Zero) { Native.HidD_FreePreparsedData(preparsed); }
                Native.CloseHandle(handle);
            }
        }
    }

    // ---------- CTAPHID transport + CTAP2 commands ----------
    public class Ctap2Device : IDisposable {
        private const int PacketSize = 64;
        private const uint BroadcastChannel = 0xFFFFFFFF;
        private const byte CmdInit = 0x86;
        private const byte CmdCbor = 0x90;      // 0x10 with the high bit set
        private const byte CmdCancel = 0x91;    // 0x11 with the high bit set
        private const byte CmdKeepAlive = 0xBB; // 0x3B with the high bit set
        private const byte CmdError = 0xBF;     // 0x3F with the high bit set

        private const byte CtapMakeCredential = 0x01;
        private const byte CtapGetAssertion = 0x02;
        private const byte CtapGetInfo = 0x04;
        private const byte CtapClientPin = 0x06;

        private IntPtr handle = new IntPtr(-1);
        private FileStream stream;
        private uint channel = BroadcastChannel;
        private int reportLength = 65;

        public string DevicePath { get; private set; }

        public Ctap2Device(string path) {
            DevicePath = path;
            handle = Native.CreateFile(path, Native.GENERIC_READ | Native.GENERIC_WRITE,
                Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero, Native.OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1)) {
                throw new Ctap2Exception("Cannot open FIDO device (is another program using it?): " + path);
            }
            Microsoft.Win32.SafeHandles.SafeFileHandle safe =
                new Microsoft.Win32.SafeHandles.SafeFileHandle(handle, false);
            stream = new FileStream(safe, FileAccess.ReadWrite, reportLength, false);
            Init();
        }

        public void Dispose() {
            if (stream != null) { stream.Dispose(); stream = null; }
            if (handle != new IntPtr(-1)) { Native.CloseHandle(handle); handle = new IntPtr(-1); }
        }

        private void WritePacket(byte[] packet) {
            byte[] report = new byte[reportLength];
            report[0] = 0; // HID report id
            Array.Copy(packet, 0, report, 1, Math.Min(packet.Length, reportLength - 1));
            stream.Write(report, 0, report.Length);
            stream.Flush();
        }

        private byte[] ReadPacket() {
            byte[] report = new byte[reportLength];
            int read = stream.Read(report, 0, report.Length);
            if (read <= 0) { throw new Ctap2Exception("FIDO device returned no data"); }
            byte[] packet = new byte[PacketSize];
            Array.Copy(report, 1, packet, 0, PacketSize);
            return packet;
        }

        private static void WriteChannel(byte[] packet, uint cid) {
            packet[0] = (byte)(cid >> 24); packet[1] = (byte)(cid >> 16);
            packet[2] = (byte)(cid >> 8);  packet[3] = (byte)cid;
        }

        private void SendMessage(byte command, byte[] payload) {
            if (payload == null) { payload = new byte[0]; }

            byte[] initPacket = new byte[PacketSize];
            WriteChannel(initPacket, channel);
            initPacket[4] = command;
            initPacket[5] = (byte)(payload.Length >> 8);
            initPacket[6] = (byte)payload.Length;

            int firstChunk = Math.Min(payload.Length, PacketSize - 7);
            Array.Copy(payload, 0, initPacket, 7, firstChunk);
            WritePacket(initPacket);

            int sent = firstChunk;
            byte sequence = 0;
            while (sent < payload.Length) {
                byte[] cont = new byte[PacketSize];
                WriteChannel(cont, channel);
                cont[4] = sequence++;
                int chunk = Math.Min(payload.Length - sent, PacketSize - 5);
                Array.Copy(payload, sent, cont, 5, chunk);
                WritePacket(cont);
                sent += chunk;
            }
        }

        private byte[] ReceiveMessage(byte expectedCommand, int timeoutMs) {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);

            while (true) {
                if (DateTime.UtcNow > deadline) {
                    throw new Ctap2Exception("Timed out waiting for the security key");
                }

                byte[] packet = ReadPacket();
                uint cid = ((uint)packet[0] << 24) | ((uint)packet[1] << 16) | ((uint)packet[2] << 8) | packet[3];
                if (cid != channel) { continue; }

                byte command = packet[4];
                if (command == CmdKeepAlive) {
                    // Status 0x02 means "waiting for user presence" - the
                    // token is asking for a touch. Keep reading.
                    continue;
                }
                if (command == CmdError) {
                    throw new Ctap2Exception("CTAPHID error from device: 0x" + packet[7].ToString("x2"));
                }
                if (command != expectedCommand) { continue; }

                int length = (packet[5] << 8) | packet[6];
                byte[] payload = new byte[length];
                int firstChunk = Math.Min(length, PacketSize - 7);
                Array.Copy(packet, 7, payload, 0, firstChunk);
                int received = firstChunk;

                while (received < length) {
                    byte[] cont = ReadPacket();
                    uint contCid = ((uint)cont[0] << 24) | ((uint)cont[1] << 16) | ((uint)cont[2] << 8) | cont[3];
                    if (contCid != channel) { continue; }
                    int chunk = Math.Min(length - received, PacketSize - 5);
                    Array.Copy(cont, 5, payload, received, chunk);
                    received += chunk;
                }
                return payload;
            }
        }

        private void Init() {
            byte[] nonce = new byte[8];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { rng.GetBytes(nonce); }

            channel = BroadcastChannel;
            SendMessage(CmdInit, nonce);

            DateTime deadline = DateTime.UtcNow.AddMilliseconds(3000);
            while (DateTime.UtcNow <= deadline) {
                byte[] response = ReceiveMessage(CmdInit, 3000);
                if (response.Length < 17) { continue; }
                bool matches = true;
                for (int i = 0; i < 8; i++) { if (response[i] != nonce[i]) { matches = false; break; } }
                if (!matches) { continue; } // another client's INIT reply
                channel = ((uint)response[8] << 24) | ((uint)response[9] << 16) |
                          ((uint)response[10] << 8) | response[11];
                return;
            }
            throw new Ctap2Exception("Security key did not answer CTAPHID_INIT");
        }

        private Dictionary<object, object> SendCbor(byte command, byte[] parameters, int timeoutMs) {
            byte[] payload = new byte[1 + (parameters == null ? 0 : parameters.Length)];
            payload[0] = command;
            if (parameters != null) { Array.Copy(parameters, 0, payload, 1, parameters.Length); }

            SendMessage(CmdCbor, payload);
            byte[] response = ReceiveMessage(CmdCbor, timeoutMs);

            if (response.Length < 1) { throw new Ctap2Exception("Empty CTAP2 response"); }
            byte status = response[0];
            if (status != 0x00) {
                throw new Ctap2Exception(DescribeStatus(status), status);
            }
            if (response.Length == 1) { return new Dictionary<object, object>(); }

            int offset = 1;
            object decoded = Cbor.Decode(response, ref offset);
            Dictionary<object, object> map = decoded as Dictionary<object, object>;
            if (map == null) { throw new Ctap2Exception("CTAP2 response was not a map"); }
            return map;
        }

        public static string DescribeStatus(byte status) {
            switch (status) {
                case 0x31: return "The security key rejected the PIN (CTAP2_ERR_PIN_INVALID)";
                case 0x32: return "The security key is PIN-blocked and must be reset (CTAP2_ERR_PIN_BLOCKED)";
                case 0x33: return "PIN authentication is temporarily blocked; unplug and reinsert the key (CTAP2_ERR_PIN_AUTH_BLOCKED)";
                case 0x34: return "This security key has no PIN set (CTAP2_ERR_PIN_NOT_SET)";
                case 0x35: return "The security key requires a PIN (CTAP2_ERR_PIN_REQUIRED)";
                case 0x36: return "PIN policy violation (CTAP2_ERR_PIN_POLICY_VIOLATION)";
                case 0x2E: return "The security key requires user verification (CTAP2_ERR_UNSUPPORTED_OPTION or UV required)";
                case 0x27: return "Credential not present on this security key (CTAP2_ERR_NO_CREDENTIALS)";
                case 0x2B: return "No matching credential on this security key (CTAP2_ERR_NO_CREDENTIALS)";
                case 0x3A: return "Touch timed out (CTAP2_ERR_USER_ACTION_TIMEOUT)";
                case 0x19: return "Operation already pending on this key (CTAP2_ERR_CHANNEL_BUSY)";
                default: return "Security key returned CTAP2 error 0x" + status.ToString("x2");
            }
        }

        public Dictionary<object, object> GetInfo() {
            return SendCbor(CtapGetInfo, null, 3000);
        }

        // ----- PIN/UV auth protocol one -----
        // sharedSecret = SHA-256(ECDH(platform, authenticator).x), which is
        // exactly what ECDiffieHellmanCng produces with Hash/SHA-256 because
        // CNG's secret agreement is the x-coordinate.
        private class KeyAgreement {
            public byte[] SharedSecret;
            public byte[] PlatformX;
            public byte[] PlatformY;
        }

        private KeyAgreement Agree(byte[] authenticatorX, byte[] authenticatorY) {
            CngKeyCreationParameters creationParameters = new CngKeyCreationParameters();
            creationParameters.ExportPolicy = CngExportPolicies.AllowPlaintextExport;
            creationParameters.KeyUsage = CngKeyUsages.AllUsages;

            using (CngKey platformKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, null, creationParameters))
            using (ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(platformKey)) {
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ecdh.HashAlgorithm = CngAlgorithm.Sha256;

                byte[] platformBlob = platformKey.Export(CngKeyBlobFormat.EccPublicBlob);
                byte[] platformX = new byte[32];
                byte[] platformY = new byte[32];
                Array.Copy(platformBlob, 8, platformX, 0, 32);
                Array.Copy(platformBlob, 40, platformY, 0, 32);

                // BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345, key size 32.
                byte[] peerBlob = new byte[8 + 64];
                BitConverter.GetBytes(0x314B4345).CopyTo(peerBlob, 0);
                BitConverter.GetBytes(32).CopyTo(peerBlob, 4);
                Array.Copy(authenticatorX, 0, peerBlob, 8, 32);
                Array.Copy(authenticatorY, 0, peerBlob, 40, 32);

                using (CngKey peerKey = CngKey.Import(peerBlob, CngKeyBlobFormat.EccPublicBlob)) {
                    KeyAgreement agreement = new KeyAgreement();
                    agreement.SharedSecret = ecdh.DeriveKeyMaterial(peerKey);
                    agreement.PlatformX = platformX;
                    agreement.PlatformY = platformY;
                    return agreement;
                }
            }
        }

        private KeyAgreement GetKeyAgreement() {
            MemoryStream request = new MemoryStream();
            Cbor.WriteMapHead(request, 2);
            Cbor.WriteInt(request, 1); Cbor.WriteInt(request, 1);  // pinUvAuthProtocol = 1
            Cbor.WriteInt(request, 2); Cbor.WriteInt(request, 2);  // subCommand = getKeyAgreement
            Dictionary<object, object> response = SendCbor(CtapClientPin, request.ToArray(), 3000);

            Dictionary<object, object> coseKey = response[1L] as Dictionary<object, object>;
            if (coseKey == null) { throw new Ctap2Exception("Security key did not return a key agreement"); }
            byte[] x = (byte[])coseKey[-2L];
            byte[] y = (byte[])coseKey[-3L];
            return Agree(x, y);
        }

        private static byte[] AesCbcZeroIv(byte[] key, byte[] data, bool encrypt) {
            using (Aes aes = Aes.Create()) {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None; // CTAP2 pads nothing; sizes are already block-aligned
                aes.Key = key;
                aes.IV = new byte[16];
                using (ICryptoTransform transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor()) {
                    return transform.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        private static byte[] Left16(byte[] input) {
            byte[] output = new byte[16];
            Array.Copy(input, 0, output, 0, 16);
            return output;
        }

        private byte[] GetPinToken(KeyAgreement agreement, string pin) {
            byte[] pinHash;
            using (SHA256 sha = SHA256.Create()) {
                pinHash = Left16(sha.ComputeHash(Encoding.UTF8.GetBytes(pin)));
            }
            byte[] pinHashEnc = AesCbcZeroIv(agreement.SharedSecret, pinHash, true);

            MemoryStream request = new MemoryStream();
            Cbor.WriteMapHead(request, 4);
            Cbor.WriteInt(request, 1); Cbor.WriteInt(request, 1);  // pinUvAuthProtocol
            Cbor.WriteInt(request, 2); Cbor.WriteInt(request, 5);  // subCommand = getPINToken
            Cbor.WriteInt(request, 3);                              // keyAgreement (COSE)
            WriteCoseKey(request, agreement.PlatformX, agreement.PlatformY);
            Cbor.WriteInt(request, 6); Cbor.WriteBytes(request, pinHashEnc);

            Dictionary<object, object> response = SendCbor(CtapClientPin, request.ToArray(), 5000);
            byte[] encryptedToken = (byte[])response[2L];
            return AesCbcZeroIv(agreement.SharedSecret, encryptedToken, false);
        }

        private static void WriteCoseKey(MemoryStream stream, byte[] x, byte[] y) {
            Cbor.WriteMapHead(stream, 5);
            Cbor.WriteInt(stream, 1); Cbor.WriteInt(stream, 2);    // kty = EC2
            Cbor.WriteInt(stream, 3); Cbor.WriteInt(stream, -25);  // alg = ECDH-ES+HKDF-256
            Cbor.WriteInt(stream, -1); Cbor.WriteInt(stream, 1);   // crv = P-256
            Cbor.WriteInt(stream, -2); Cbor.WriteBytes(stream, x);
            Cbor.WriteInt(stream, -3); Cbor.WriteBytes(stream, y);
        }

        private static byte[] HmacSha256(byte[] key, byte[] data) {
            using (HMACSHA256 hmac = new HMACSHA256(key)) { return hmac.ComputeHash(data); }
        }

        public bool HasClientPin() {
            Dictionary<object, object> info = GetInfo();
            if (!info.ContainsKey(4L)) { return false; }
            Dictionary<object, object> options = info[4L] as Dictionary<object, object>;
            if (options == null || !options.ContainsKey("clientPin")) { return false; }
            return (bool)options["clientPin"];
        }

        public bool SupportsHmacSecret() {
            Dictionary<object, object> info = GetInfo();
            if (!info.ContainsKey(2L)) { return false; }
            List<object> extensions = info[2L] as List<object>;
            if (extensions == null) { return false; }
            foreach (object extension in extensions) {
                if ((extension as string) == "hmac-secret") { return true; }
            }
            return false;
        }

        // Creates a non-resident credential carrying hmac-secret. Returns the
        // credential id, which the caller stores in the key slot; the secret
        // it derives never leaves the token.
        public byte[] MakeHmacSecretCredential(string rpId, string userName, string pin, int timeoutMs) {
            byte[] clientDataHash = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { rng.GetBytes(clientDataHash); }
            byte[] userId = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { rng.GetBytes(userId); }

            byte[] pinAuth = null;
            if (!string.IsNullOrEmpty(pin)) {
                KeyAgreement agreement = GetKeyAgreement();
                byte[] pinToken = GetPinToken(agreement, pin);
                pinAuth = Left16(HmacSha256(pinToken, clientDataHash));
                Array.Clear(pinToken, 0, pinToken.Length);
            }

            MemoryStream request = new MemoryStream();
            Cbor.WriteMapHead(request, pinAuth == null ? 6 : 8);
            Cbor.WriteInt(request, 1); Cbor.WriteBytes(request, clientDataHash);
            Cbor.WriteInt(request, 2);
                Cbor.WriteMapHead(request, 2);
                Cbor.WriteText(request, "id"); Cbor.WriteText(request, rpId);
                Cbor.WriteText(request, "name"); Cbor.WriteText(request, "shush vault");
            Cbor.WriteInt(request, 3);
                Cbor.WriteMapHead(request, 3);
                Cbor.WriteText(request, "id"); Cbor.WriteBytes(request, userId);
                Cbor.WriteText(request, "name"); Cbor.WriteText(request, userName);
                Cbor.WriteText(request, "displayName"); Cbor.WriteText(request, userName);
            Cbor.WriteInt(request, 4);
                Cbor.WriteArrayHead(request, 1);
                Cbor.WriteMapHead(request, 2);
                Cbor.WriteText(request, "alg"); Cbor.WriteInt(request, -7);   // ES256
                Cbor.WriteText(request, "type"); Cbor.WriteText(request, "public-key");
            Cbor.WriteInt(request, 6);
                Cbor.WriteMapHead(request, 1);
                Cbor.WriteText(request, "hmac-secret"); Cbor.WriteBool(request, true);
            Cbor.WriteInt(request, 7);
                Cbor.WriteMapHead(request, 1);
                Cbor.WriteText(request, "rk"); Cbor.WriteBool(request, false);
            if (pinAuth != null) {
                Cbor.WriteInt(request, 8); Cbor.WriteBytes(request, pinAuth);
                Cbor.WriteInt(request, 9); Cbor.WriteInt(request, 1);
            }

            Dictionary<object, object> response = SendCbor(CtapMakeCredential, request.ToArray(), timeoutMs);
            byte[] authData = (byte[])response[2L];
            return ExtractCredentialId(authData);
        }

        // authData: rpIdHash(32) | flags(1) | signCount(4) | attestedCredentialData
        // attestedCredentialData: aaguid(16) | credentialIdLength(2, big endian) | credentialId
        private static byte[] ExtractCredentialId(byte[] authData) {
            if (authData.Length < 55) { throw new Ctap2Exception("Authenticator data too short for a credential"); }
            byte flags = authData[32];
            if ((flags & 0x40) == 0) { throw new Ctap2Exception("Authenticator returned no attested credential data"); }
            int offset = 37 + 16;
            int credentialIdLength = (authData[offset] << 8) | authData[offset + 1];
            offset += 2;
            byte[] credentialId = new byte[credentialIdLength];
            Array.Copy(authData, offset, credentialId, 0, credentialIdLength);
            return credentialId;
        }

        // Derives the 32-byte hmac-secret output for the given salt. The same
        // credential + salt + UV state always yields the same bytes, which is
        // what makes this usable as a key-encryption key.
        public byte[] GetHmacSecret(string rpId, byte[] credentialId, byte[] salt, string pin, int timeoutMs) {
            if (salt.Length != 32) { throw new Ctap2Exception("hmac-secret salt must be 32 bytes"); }

            KeyAgreement agreement = GetKeyAgreement();
            byte[] saltEnc = AesCbcZeroIv(agreement.SharedSecret, salt, true);
            byte[] saltAuth = Left16(HmacSha256(agreement.SharedSecret, saltEnc));

            byte[] clientDataHash = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { rng.GetBytes(clientDataHash); }

            byte[] pinAuth = null;
            if (!string.IsNullOrEmpty(pin)) {
                byte[] pinToken = GetPinToken(agreement, pin);
                pinAuth = Left16(HmacSha256(pinToken, clientDataHash));
                Array.Clear(pinToken, 0, pinToken.Length);
            }

            MemoryStream request = new MemoryStream();
            Cbor.WriteMapHead(request, pinAuth == null ? 4 : 6);
            Cbor.WriteInt(request, 1); Cbor.WriteText(request, rpId);
            Cbor.WriteInt(request, 2); Cbor.WriteBytes(request, clientDataHash);
            Cbor.WriteInt(request, 3);
                Cbor.WriteArrayHead(request, 1);
                Cbor.WriteMapHead(request, 2);
                Cbor.WriteText(request, "id"); Cbor.WriteBytes(request, credentialId);
                Cbor.WriteText(request, "type"); Cbor.WriteText(request, "public-key");
            Cbor.WriteInt(request, 4);
                Cbor.WriteMapHead(request, 1);
                Cbor.WriteText(request, "hmac-secret");
                Cbor.WriteMapHead(request, 3);
                Cbor.WriteInt(request, 1); WriteCoseKey(request, agreement.PlatformX, agreement.PlatformY);
                Cbor.WriteInt(request, 2); Cbor.WriteBytes(request, saltEnc);
                Cbor.WriteInt(request, 3); Cbor.WriteBytes(request, saltAuth);
            if (pinAuth != null) {
                Cbor.WriteInt(request, 6); Cbor.WriteBytes(request, pinAuth);
                Cbor.WriteInt(request, 7); Cbor.WriteInt(request, 1);
            }

            Dictionary<object, object> response = SendCbor(CtapGetAssertion, request.ToArray(), timeoutMs);
            byte[] authData = (byte[])response[2L];
            byte[] encryptedOutput = ExtractHmacSecretOutput(authData);

            byte[] output = AesCbcZeroIv(agreement.SharedSecret, encryptedOutput, false);
            Array.Clear(agreement.SharedSecret, 0, agreement.SharedSecret.Length);

            // Only salt1 was sent, so only the first 32 bytes are ours.
            byte[] result = new byte[32];
            Array.Copy(output, 0, result, 0, 32);
            Array.Clear(output, 0, output.Length);
            return result;
        }

        // Assertion authData carries no attested credential data, so the
        // extension map starts right after signCount at offset 37.
        private static byte[] ExtractHmacSecretOutput(byte[] authData) {
            if (authData.Length < 38) { throw new Ctap2Exception("Authenticator data too short for extensions"); }
            byte flags = authData[32];
            if ((flags & 0x80) == 0) {
                throw new Ctap2Exception("Security key returned no hmac-secret output; the credential may not carry the extension");
            }
            int offset = 37;
            if ((flags & 0x40) != 0) {
                // Attested credential data present (unusual for an assertion).
                offset += 16;
                int credentialIdLength = (authData[offset] << 8) | authData[offset + 1];
                offset += 2 + credentialIdLength;
                Cbor.Decode(authData, ref offset); // skip the COSE public key
            }
            object decoded = Cbor.Decode(authData, ref offset);
            Dictionary<object, object> extensions = decoded as Dictionary<object, object>;
            if (extensions == null || !extensions.ContainsKey("hmac-secret")) {
                throw new Ctap2Exception("Security key did not return the hmac-secret extension");
            }
            return (byte[])extensions["hmac-secret"];
        }
    }
}
'@ @script:addTypeReferences
}

function get_fido2_devices {
    initialize_fido2_native
    try {
        $devices = [Shush.Fido2.HidEnumerator]::Enumerate()
        return @{ success = $true; data = @($devices); error = $null }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'FIDO2_ENUMERATE_FAILED'; message = "Cannot enumerate FIDO2 devices: $($_.Exception.Message)" }
        }
    }
}

function open_fido2_device {
    param([string]$Path)

    initialize_fido2_native
    try {
        return @{ success = $true; data = [Shush.Fido2.Ctap2Device]::new($Path); error = $null }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'FIDO2_OPEN_FAILED'; message = $_.Exception.Message }
        }
    }
}

Export-ModuleMember -Function @(
    'initialize_fido2_native',
    'get_fido2_devices',
    'open_fido2_device'
)
