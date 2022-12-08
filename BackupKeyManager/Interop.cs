﻿using System;
using System.Runtime.InteropServices;

namespace BackupKeyManager
{
    public class Interop
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public LSA_UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        // Information taken from MS-BKRP protocol [2.2.5]
        [StructLayout(LayoutKind.Sequential)]
        public struct DOMAIN_BACKUP_KEY
        {
            public uint bkpVersion;             // backup key version - 02 00 00 00 // 2
            public uint cspLen;                 // Csp blob length - Must be: 94 04 00 00 = 1172 (This length represents 2048 bit key)
            public uint certificateLength;      // The certificate length
            public IntPtr cspBlobPtr;
            public IntPtr certificatePtr;
            public void AllocBkpData(byte[] bkpBytes, int cspLen, int certLen)
            {
                cspBlobPtr = Marshal.AllocHGlobal(cspLen);
                Marshal.Copy(bkpBytes, 12, cspBlobPtr, cspLen);  // Start copying after the header
                certificatePtr = Marshal.AllocHGlobal(certLen);
                Marshal.Copy(bkpBytes, 12+cspLen, certificatePtr, certLen);  // Start copying after the header + csp size
            }
            public void AllocKeyData(byte[] cspBytes, byte[] certBytes)
            {
                var cspLen = cspBytes.Length;
                var certLen = certBytes.Length;
                cspBlobPtr = Marshal.AllocHGlobal(cspLen);
                Marshal.Copy(cspBytes, 0, cspBlobPtr, cspLen);
                
                certificatePtr = Marshal.AllocHGlobal(certLen);
                Marshal.Copy(certBytes, 0, certificatePtr, certLen);
            }
            public void FreePtrs()
            {
                Marshal.FreeHGlobal(cspBlobPtr);
                Marshal.FreeHGlobal(certificatePtr);
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct BACKUP_KEY_PUB_CERT_INFO
        {
            public System.Numerics.BigInteger certSerial;
            public byte[] certVersionByte;
            public string certIssuerStr;
            public string certSubjectStr;
            public DateTimeOffset certNotBefore;
            public DateTimeOffset certNotAfter;
            public string signatureAlgorithmOID;
            public string subjectPublicKeyInfoOID;
            public System.Numerics.BigInteger subjectPublicKeyInfoRSAKey;
            public Guid asnCtx1CertGuid;
            public Guid asnCtx2CertGuid;
        }

        public enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L,
            POLICY_ALL = 0x10000000L
        }

        public enum LSA_AccessSecret : long
        {
            SECRET_SET_VALUE = 0x00000001L,
            SECRET_QUERY_VALUE = 0x00000002L,
        }

        public struct LSA_OBJECT_ATTRIBUTES
        {
            public UInt32 Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        // for remote backup key retrieval
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaOpenPolicy(
           ref LSA_UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaRetrievePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaStorePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            ref LSA_UNICODE_STRING PrivateData
        );
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaCreateSecret(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            uint DesiredAccess,
            out IntPtr SecretHandle
        );
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaOpenSecret(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            uint DesiredAccess,
            out IntPtr SecretHandle
        );
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaSetSecret(
            IntPtr SecretHandle,
            ref LSA_UNICODE_STRING PrivateData,
            ref LSA_UNICODE_STRING OldPrivateData
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaClose(IntPtr ObjectHandle);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaFreeMemory(
            IntPtr buffer
        );


        [DllImport("MS-BKRP.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool get_bkrp_cert(
        String dc,
        ref IntPtr pDataOut,
        ref int pDataSize
        );

        [DllImport("MS-BKRP.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool bkrp_test(String dc);

        [DllImport("MS-BKRP.dll", SetLastError = true)]
        public static extern void free_bkrp(IntPtr ptr);

    }
}