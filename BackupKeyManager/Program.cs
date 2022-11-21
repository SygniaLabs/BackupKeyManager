using System;
using System.Text;
using System.IO;
using CommandLine;
using System.Linq;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;



namespace BackupKeyManager
{

    class Program
    {
        [Verb("GetPublicKey", HelpText = "Fetch the public certificate of the preferred BackupKey via MS-BKRP (Non-Admin operation).")]
        class FetchBackupKeyCert_Opts
        {
            [Option('s', "DomainController", Required = true, HelpText = "Primary Domain Controller FQDN to interact with.")]
            public string DomainController { get; set; }

            [Option("analyze", Required = false, HelpText = "(Optional) Print information about the fetched certificate.")]
            public bool analyze { get; set; }

            [Option('o', Required = false, HelpText = "(Optional) Flag to save the certificate to a file (DER format) in the current path.")]
            public bool OutputFile { get; set; }
        }

        [Verb("GetBackupKey", HelpText = "Get a BackupKey. By default will get the preferred (currently used) one.")]
        class GetBackupKey_Opts
        {
            [Option('s', "DomainController", Required = true, HelpText = "Primary Domain Controller FQDN to interact with")]
            public string DomainController { get; set; }
            
            [Option("GUID", Required = false, HelpText = "(Optional) Specify non-preferred BackupKey GUID to get (e.g. XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX).")]
            public string GUID { get; set; }

            [Option('o', Required = false, HelpText = "(Optional) Flag to save the Backupkey and certificate (DER format) outputs to files in the current path.")]
            public bool OutputFile { get; set; }
            
            [Option("analyze", Required = false, HelpText = "(Optional) Analyze the exported BackupKey")]
            public bool analyze { get; set; }
        }


        [Verb("SetPreferredBackupKey", HelpText = "Set a new preferred BackupKey by providing its GUID")]
        class SetPreferredBackupKeyByGUID_Opts
        {
            [Option('s', "DomainController", Required = true, HelpText = "Primary Domain Controller FQDN to interact with")]
            public string DomainController { get; set; }

            [Option("GUID", Required = true, HelpText = "A GUID format string for the required action (e.g. XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)")]
            public string GUID { get; set; }
        }

        [Verb("GenerateNewBackupKey", HelpText = "Generate new BackupKey with option to push and set as preferred.")]
        class GenerateNewBackupKey_Opts
        {
            [Option('d', "DomainName", Required = true, HelpText = "FQDN of the targeted domain. This will be included in the public certificate.")]
            public string DomainName { get; set; }

            [Option('o', Required = false, HelpText = "(Optional) Flag to save the Backupkey and certificate (DER format) outputs to files in the current path.")]
            public bool OutputFile { get; set; }

            [Option("push", Required = false, HelpText = "(Optional) Push the generated BackupKey to a Domain Controller.")]
            public bool push { get; set; }

            [Option('s', "DomainController", Required = false, HelpText = "(Required with 'push') Primary Domain Controller FQDN to interact with.")]
            public string DomainController { get; set; }
           
            [Option("set", Required = false, HelpText = "(Required with 'push') Set the generated BackupKey as the Preferred BackupKey.")]
            public bool set { get; set; }
        }

        [Verb("BackupKeyFromFile", HelpText = "Load BackupKey from file with option to push and set as preferred.")]
        class CreateBackupKeyFromFile_Opts
        {
            [Option('i', "InputFile", Required = true, HelpText = "BackupKey input file in the dumped/created format - '.dpapibkp'")]
            public string InputFile { get; set; }

            [Option("push", Required = false, HelpText = "(Optional) Push the loaded BackupKey to a Domain Controller.")]
            public bool push { get; set; }

            [Option('s', "DomainController", Required = false, HelpText = "(Required with 'push') Primary Domain Controller FQDN to interact with.")]
            public string DomainController { get; set; }

            [Option("set", Required = false, HelpText = "(Required with 'push') Set the loaded BackupKey as the Preferred BackupKey.")]
            public bool set { get; set; }
        }

        [Verb("Validate", HelpText = "Validates the BackupKey setup. Validation should be made against all DCs in the domain.")]
        class CheckBackupKey_Opts
        {
            [Option('s', "DomainController", Required = true, HelpText = "Domain Controller FQDN to interact with.")]
            public string DomainController { get; set; }
        }




        // Backup Key Cosntants
        private static readonly uint BackupKeyVersion = 2;
        private static readonly uint BackupKeyCspByteLength = 1172;  // CSP Length for 2048 bit Key Len
        private static readonly int BackupKeyBitLength = 2048;
        private static readonly string SignatureAlgOidOddballOIW = "1.3.14.3.2.29";
        private static readonly int CertificateValidityPeriodYears = 1;
        private static readonly int CertificateVersion = 0x2;
        private static readonly int CertificateSerialNumberByteLen = 16;
        private static readonly byte AsnSeqTag = 0x30; //Asn tag for Sequence
        private static readonly byte AsnSetTag = 0x31; // Asn tag for SET
        private static readonly byte AsnPrintableStringTag = 0x13;  // Asn tag for PrintableString
        private static readonly byte[] AsnCommonName = { 0x06, 0x03, 0x55, 0x04, 0x03 }; // ASN Bytes for commonName
        private static readonly byte AsnContextSpecific1Tag = 0x81;
        private static readonly byte AsnContextSpecific2Tag = 0x82;
        private static readonly byte AsnGuidLengthWithSign = 0x11;
        private static readonly byte AsnGuidByteSign = 0x00;


        public static bool checkNTstatus(uint ntStatus, string calledFunction, bool continueOnError = false)
        {

            if (ntStatus != 0)
            {
                uint winErrorCode = Interop.LsaNtStatusToWinError(ntStatus);
                string errorMessage = new Win32Exception((int)winErrorCode).Message;
                Console.WriteLine("  [!] Error calling {0}, ErrCode: {1}, ErrMsg: {2}", calledFunction, winErrorCode, errorMessage);
                if (!continueOnError) { throw new InvalidOperationException("Error calling " + calledFunction); }
                return false;
            }
            else
            {
                return true;
            }

        }

        public static Guid GetPreferredBackupGUID(IntPtr LsaPolicyHandle)
        {
           
            Interop.LSA_UNICODE_STRING secretName = new Interop.LSA_UNICODE_STRING("G$BCKUPKEY_PREFERRED");

            uint ntsResult = Interop.LsaRetrievePrivateData(LsaPolicyHandle, ref secretName, out IntPtr PrivateData);
            checkNTstatus(ntsResult, "LsaRetrievePrivateData");

            Interop.LSA_UNICODE_STRING lusSecretData = 
                (Interop.LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateData, typeof(Interop.LSA_UNICODE_STRING));
            Marshal.FreeHGlobal(PrivateData);

            byte[] guidBytes = new byte[lusSecretData.Length];
            Marshal.Copy(lusSecretData.buffer, guidBytes, 0, lusSecretData.Length);  // Copy the GUID bytes from the secret data
            //Interop.LsaFreeMemory(lusSecretData.buffer);

            Guid backupKeyGuid = new Guid(guidBytes);

            return backupKeyGuid;

        }

        public static void SetPreferredBackupKeyByGUID(IntPtr LsaPolicyHandle, Guid newPreferredGUID)
        {

            string guidStrBytes = System.Text.Encoding.Unicode.GetString(newPreferredGUID.ToByteArray());
            Interop.LSA_UNICODE_STRING privateData = new Interop.LSA_UNICODE_STRING(guidStrBytes);
            Interop.LSA_UNICODE_STRING secretName = new Interop.LSA_UNICODE_STRING("G$BCKUPKEY_PREFERRED");


            //IntPtr secretNamePointer = Marshal.AllocHGlobal(Marshal.SizeOf(secretName));
            //Marshal.StructureToPtr(secretName, secretNamePointer, false);

            //IntPtr privateDataPointer = Marshal.AllocHGlobal(Marshal.SizeOf(privateData));
            //Marshal.StructureToPtr(privateData, privateDataPointer, false);

            // Store the new Guid in BCKUPKEY_PREFERRED
            uint ntsResult = Interop.LsaStorePrivateData(LsaPolicyHandle, ref secretName, ref privateData);
            checkNTstatus(ntsResult, "LsaStorePrivateData");

            Console.WriteLine($"[+] Modified preferred backup GUID to: {newPreferredGUID}");
            Console.WriteLine("\r\n[?] You must restart the targeted Domain Controller for the changes to take effect");

        }

        public static byte[] GetBackupKeyByGUID(IntPtr LsaPolicyHandle, Guid backupKeyGuid)
        {
                       
            string backupKeyName = String.Format("G$BCKUPKEY_{0}", backupKeyGuid.ToString());
            Console.WriteLine("[+] Getting backup key     : {0}", backupKeyName);
            

            Interop.LSA_UNICODE_STRING backupKeyLSA = new Interop.LSA_UNICODE_STRING(backupKeyName);

            // retrieve the bytes of the full DPAPI private backup key
            uint ntsResult = Interop.LsaRetrievePrivateData(LsaPolicyHandle, ref backupKeyLSA, out IntPtr PrivateData);            
            if (!checkNTstatus(ntsResult, "LsaRetrievePrivateData")) { return null; }

            try
            {
                Interop.LSA_UNICODE_STRING backupKeyBytesLSA = (Interop.LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateData, typeof(Interop.LSA_UNICODE_STRING));
                Marshal.FreeHGlobal(PrivateData);

                byte[] backupKeyBytes = new byte[backupKeyBytesLSA.Length];
                Marshal.Copy(backupKeyBytesLSA.buffer, backupKeyBytes, 0, backupKeyBytesLSA.Length);
                //Interop.LsaFreeMemory(backupKeyBytesLSA.buffer);

                Console.WriteLine("[+] BackupKey size: {0}", backupKeyBytes.Length);
                return backupKeyBytes;
            }
            catch
            {
                return null;
            }
        }

        public static IntPtr GetBackupKeyHandleByGuid(IntPtr LsaPolicyHandle, Guid BackupKeyGuid, bool continueOnError = false)
        {

            string BackupKeyName = String.Format("G$BCKUPKEY_{0}", BackupKeyGuid.ToString());
            Console.WriteLine("[+] Getting handle of BackupKey     : {0}", BackupKeyName);
            
            Interop.LSA_UNICODE_STRING BackupKeyNameLSA = new Interop.LSA_UNICODE_STRING(BackupKeyName);

            uint ntsResult = Interop.LsaOpenSecret(LsaPolicyHandle, ref BackupKeyNameLSA, (uint)Interop.LSA_AccessSecret.SECRET_SET_VALUE, out IntPtr BackupKeySecretHandle);

            checkNTstatus(ntsResult, "LsaOpenSecret", continueOnError);

            Console.WriteLine("[+] Handle to Backup Key     : {0}  ->  {1}", BackupKeyName, BackupKeySecretHandle.ToString());
            return BackupKeySecretHandle;
        }

        public static IntPtr CreateNewBackupKey(IntPtr LsaPolicyHandle, Guid NewBackupKeyGuid)
        {
            // Set secret prefix
            string NewBackupKeyName = String.Format("G$BCKUPKEY_{0}", NewBackupKeyGuid.ToString());
            Console.WriteLine("[+] Creating Backup key with name     : {0}", NewBackupKeyName);
            Interop.LSA_UNICODE_STRING NewBackupKeyNameLSA = new Interop.LSA_UNICODE_STRING(NewBackupKeyName);


            uint ntsResult = Interop.LsaCreateSecret(LsaPolicyHandle, ref NewBackupKeyNameLSA, (uint)Interop.LSA_AccessPolicy.POLICY_CREATE_SECRET, out IntPtr NewBackupKeySecretHandle);

            checkNTstatus(ntsResult, "LsaCreateSecret");

            Console.WriteLine("[+] New Backup key created successfully     : {0}", NewBackupKeyName);
            return NewBackupKeySecretHandle;
        }

        public static void SetBackupKeyValue(IntPtr BackupKeyHandle, byte[] BackupKeyValueByte)
        {

            string BackupKeyValueStr = System.Text.Encoding.Unicode.GetString(BackupKeyValueByte);
            Interop.LSA_UNICODE_STRING BackupKeyValueStrLSA = new Interop.LSA_UNICODE_STRING(BackupKeyValueStr);

            //IntPtr BackupKeyValueStrLSAPointer = Marshal.AllocHGlobal(Marshal.SizeOf(BackupKeyValueStrLSA));
            //Marshal.StructureToPtr(BackupKeyValueStrLSA, BackupKeyValueStrLSAPointer, false);

            Console.WriteLine("[+] Writing bytes to Backup key...");
            uint ntsResult = Interop.LsaSetSecret(BackupKeyHandle, ref BackupKeyValueStrLSA, ref BackupKeyValueStrLSA);

            checkNTstatus(ntsResult, "LsaSetSecret");

            Console.WriteLine("[+] Backup key uploaded successfully");

        }

        public static Interop.DOMAIN_BACKUP_KEY GenerateDPAPIBackupKey(Guid backupKeyGuid, string domainName)
        {

            byte[] GuidByte = backupKeyGuid.ToByteArray();            
            Console.WriteLine("\r\n[+] Generating 2048 bit RSA Key pair...");
            
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(BackupKeyBitLength);
            var cspBlob = rsa.ExportCspBlob(true);

            Console.WriteLine("[+] Creating certificate"); // Accoridng to MS-BKRP [2.2.1] specification

            Helpers.RSASha1Pkcs1SignatureGenerator generator = new Helpers.RSASha1Pkcs1SignatureGenerator(rsa);
            byte[] certSerial = GuidByte.Reverse().ToArray();  // Certificate Serial to Big endian byte order
            var dn = buildDNforBkp(domainName);                // Certificate Distinguished Name
            
            var certRequest = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            var certificate = certRequest.Create(dn, generator, DateTime.UtcNow, DateTime.UtcNow.AddYears(1), certSerial);
            
            var certBytes = certificate.Export(X509ContentType.Cert);
            var certBytesWithGuid = pushGuidtoTbsCertificate(backupKeyGuid, certBytes);  // Appending key Guid to issuerUniqueID &  subjectUniqueID slots

            Console.WriteLine("[+] Building the new Domain BackupKey..."); // Accoridng to MS-BKRP [2.2.5] specification

            Interop.DOMAIN_BACKUP_KEY domainBackupKey = new Interop.DOMAIN_BACKUP_KEY();

            // Set the headers (UINT type)
            domainBackupKey.bkpVersion = BackupKeyVersion;
            domainBackupKey.cspLen = Convert.ToUInt32(cspBlob.Length);
            domainBackupKey.certificateLength = Convert.ToUInt32(certBytesWithGuid.Length);
            
            // Allocate pointers for Csp and Certificate
            domainBackupKey.AllocKeyData(cspBlob, certBytesWithGuid);

            return domainBackupKey;
        }


        public static IntPtr Initialize(string dc)
        {
            Console.WriteLine("\r\n[+] Setting up connection with Domain Controller: {0}", dc);

            Interop.LSA_OBJECT_ATTRIBUTES aObjectAttributes = new Interop.LSA_OBJECT_ATTRIBUTES();
            aObjectAttributes.Length = 0;
            aObjectAttributes.RootDirectory = IntPtr.Zero;
            aObjectAttributes.Attributes = 0;
            aObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            aObjectAttributes.SecurityQualityOfService = IntPtr.Zero;


            Interop.LSA_UNICODE_STRING dcName = new Interop.LSA_UNICODE_STRING(dc);
            uint ntsResult = Interop.LsaOpenPolicy(ref dcName, ref aObjectAttributes, (uint)Interop.LSA_AccessPolicy.POLICY_ALL, out IntPtr LsaPolicyHandle);
            checkNTstatus(ntsResult, "LsaOpenPolicy");

            return LsaPolicyHandle;

        }

        public static Interop.DOMAIN_BACKUP_KEY GetBackupKeyFromBytes(byte[] dpapiDomainBackupBytes)
        {

            
            Interop.DOMAIN_BACKUP_KEY dpapiDomainBackupKey = ByteToDomainBackupKey(dpapiDomainBackupBytes);

            if (!validateBackupKeyHeader(dpapiDomainBackupKey))
            {
                Console.WriteLine("[!] ERROR: BackupKey input is invalid or corrupted.");
                throw new InvalidOperationException("Error: BackupKey input is invalid or corrupted!");
            }


            return dpapiDomainBackupKey;
        }

        public static bool validateBackupKeyHeader(Interop.DOMAIN_BACKUP_KEY dpapiBackupKey)
        {
            Console.WriteLine("\r\n[+] Validating BackupKey header...");
            //Header validations:
            if (dpapiBackupKey.bkpVersion == BackupKeyVersion &&   // 02 00 00 00
                 dpapiBackupKey.cspLen == BackupKeyCspByteLength &&     // 94 04 00 00  - This will make sure we choose 2048 bit key.
                 dpapiBackupKey.certificateLength > 0
                 )
            {
                return true;
            }
            Console.WriteLine("[!] ERROR: BackupKey validation failed!");
            return false;
        }

        
        // Extract Certificate from BackupKey structure (extracted via MS-LSAD)
        public static byte[] ExtractMSLsadBkpCertificate(Interop.DOMAIN_BACKUP_KEY dpapiDomainBackupKey)
        {            
            int certificateSize = Convert.ToInt32(dpapiDomainBackupKey.certificateLength);
            byte[] certificateDERformat = new byte[certificateSize];
            Marshal.Copy(dpapiDomainBackupKey.certificatePtr, certificateDERformat, 0, certificateSize);
            return certificateDERformat;
        }



        // Fetches the Backup key certificate via MS-BKRP protocol over RPC. Any domain user permissions required.
        public static byte[] GetMSBkrpServicedCert(String dc)
        {

            IntPtr BkrpCertPtr = IntPtr.Zero;
            int BkrpCertSize = 0;

            if (Interop.get_bkrp_cert(dc, ref BkrpCertPtr, ref BkrpCertSize)) {
                byte[] BkrpCertBytes = new byte[BkrpCertSize];
                Marshal.Copy(BkrpCertPtr, BkrpCertBytes, 0, BkrpCertSize);
                Interop.free_bkrp(BkrpCertPtr);
                return BkrpCertBytes;
            }
            else {
                throw new InvalidOperationException("Error calling get_bkrp_cert function.");
            }
        }



        // Special decoder for the MS-BKRP certificate.
        public static Interop.BACKUP_KEY_PUB_CERT_INFO DecodeDERCertificate(byte[] certificateDERformat)
        {

            var BkpCertInfo = new Interop.BACKUP_KEY_PUB_CERT_INFO();
            
            var certASN = new AsnReader(certificateDERformat, AsnEncodingRules.DER);
            Asn1Tag asnMainTag = certASN.PeekTag();
            int asnMainTagLength = certASN.PeekContentBytes().Length;

            var seq3 = new AsnReader(certASN.PeekContentBytes(), AsnEncodingRules.DER);
            var seq9 = new AsnReader(seq3.PeekContentBytes(), AsnEncodingRules.DER);
            
            Asn1Tag asnFirstTagInMainSeq = seq3.PeekTag();
            int asnFirstTagInMainSeqLength = seq3.PeekContentBytes().Length;

            var certVersionEncoded = seq9.ReadEncodedValue();
            BkpCertInfo.certVersionByte = certVersionEncoded.ToArray().Skip(4).Take(1).ToArray(); // Version 3, should be 02.

            BkpCertInfo.certSerial = seq9.ReadInteger(); // CertificateSerialNumber (Bigint)

            BkpCertInfo.signatureAlgorithmOID = seq9.ReadSequence().ReadObjectIdentifier();  //OID 1.3.14.3.2.29 sha-1WithRSAEncryption (Oddball OIW OID)


            var certIssuer = seq9.ReadSequence().ReadSetOf().ReadSequence();  // Issuer
            certIssuer.ReadObjectIdentifier(); // 2.5.4.3 commonName (X.520 DN component)
            var certIssuerEncValue = certIssuer.ReadEncodedValue(); //PrintableString of CommonName. Exception on while trying to ReadCharacterString.
            string certIssuerStr = Encoding.Default.GetString(certIssuerEncValue.ToArray().Skip(2).ToArray());
            BkpCertInfo.certIssuerStr = certIssuerStr.Replace("\0", string.Empty);  // Issuer is stored as a UTF16 LE.


            var validDates = seq9.ReadSequence();  // Cert validity
            BkpCertInfo.certNotBefore = validDates.ReadUtcTime(); // Not before UTC time
            BkpCertInfo.certNotAfter = validDates.ReadUtcTime();  // Not after UTC time


            var certSubject = seq9.ReadSequence().ReadSetOf().ReadSequence(); //Subject
            certSubject.ReadObjectIdentifier();  // 2.5.4.3 commonName (X.520 DN component)
            var certSubjectEncValue = certSubject.ReadEncodedValue(); //PrintableString of CommonName 
            string certSubjectStr = Encoding.Default.GetString(certSubjectEncValue.ToArray().Skip(2).ToArray());
            BkpCertInfo.certSubjectStr = certSubjectStr.Replace("\0", string.Empty);  // Subject is stored as a UTF16 LE.


            var subjectPublicKeyInfo = seq9.ReadSequence(); // subjectPublicKeyInfo
            BkpCertInfo.subjectPublicKeyInfoOID = subjectPublicKeyInfo.ReadSequence().ReadObjectIdentifier(); // subjectPublicKeyInfo - OID 1.2.840.113549.1.1.1 
            byte[] subjectPublicKeyInfoBitStr = subjectPublicKeyInfo.ReadBitString(out int unusedarg);
            var subjectPublicKeyInfoBitStrReader = new AsnReader(subjectPublicKeyInfoBitStr, AsnEncodingRules.DER);
            BkpCertInfo.subjectPublicKeyInfoRSAKey = subjectPublicKeyInfoBitStrReader.ReadSequence().ReadInteger();



            var issuerUniqueIDEncoded = seq9.ReadEncodedValue(); // BackupKey encoded GUID 
            var subjectUniqueIDEncoded = seq9.ReadEncodedValue(); // BackupKey encoded GUID 
            seq9.ThrowIfNotEmpty();


            seq3.ReadSequence();            
            Asn1Tag asnSecondTagInMainSeq = seq3.PeekTag();
            int asnSecondTagInMainSeqLength = seq3.PeekContentBytes().Length;
            seq3.ReadSequence();
            Asn1Tag asnThirdTagInMainSeq = seq3.PeekTag();
            int asnThirdTagInMainSeqLength = seq3.PeekContentBytes().Length;
            seq3.ReadBitString(out int countof3BitStr);
            seq3.ThrowIfNotEmpty();

            // Closing the reader and throw exception if we missed somthing.
            certASN.ReadSequence();
            certASN.ThrowIfNotEmpty();


            byte[] CertGuidByte1 = subjectUniqueIDEncoded.ToArray().Skip(3).Take(16).ToArray(); // Transfrom from ASN1 encoded representation to Guid Bytes.
            byte[] CertGuidByte2 = issuerUniqueIDEncoded.ToArray().Skip(3).Take(16).ToArray();

            BkpCertInfo.asnCtx1CertGuid = new Guid(CertGuidByte1);
            BkpCertInfo.asnCtx2CertGuid = new Guid(CertGuidByte2);

            /*
            Console.WriteLine("[ASN] - {0}: {1}", asnMainTag, asnMainTagLength);
            Console.WriteLine("[ASN]    - {0}: {1}", asnFirstTagInMainSeq, asnFirstTagInMainSeqLength);
            Console.WriteLine("[ASN]    - {0}: {1}", asnSecondTagInMainSeq, asnSecondTagInMainSeqLength);
            Console.WriteLine("[ASN]    - {0}: {1}", asnThirdTagInMainSeq, asnThirdTagInMainSeqLength);
            */
     
            return BkpCertInfo;
        }

        
        public static void BkpCertInfoPrint(Interop.BACKUP_KEY_PUB_CERT_INFO BkpCertInfo)
        {

            Console.WriteLine("\r\n[+] Analyzing certificate information:");
            Console.WriteLine("[Certificate] Serial Number:     {0}", BitConverter.ToString(BkpCertInfo.certSerial.ToByteArray().Reverse().ToArray())); // Certificate serial number (big int) interpreted with Big endian byte order
            Console.WriteLine("[Certificate] Version:           {0}", ((int)BkpCertInfo.certVersionByte[0]) + 1); // Adding 1 to reflect the actual version.
            Console.WriteLine("[Certificate] Issuer name:       {0}", BkpCertInfo.certIssuerStr);
            Console.WriteLine("[Certificate] Subject name:      {0}", BkpCertInfo.certSubjectStr);
            Console.WriteLine("[Certificate] Not Before:        {0}", BkpCertInfo.certNotBefore);
            Console.WriteLine("[Certificate] Not After:         {0}", BkpCertInfo.certNotAfter);
            Console.WriteLine("[Certificate] Validity period:   {0}", BkpCertInfo.certNotAfter - BkpCertInfo.certNotBefore);
            Console.WriteLine("[Certificate] SignatureAlgo OID: {0}", BkpCertInfo.signatureAlgorithmOID);
            Console.WriteLine("[Certificate] PublicKeyInfo OID: {0}", BkpCertInfo.subjectPublicKeyInfoOID);
            Console.WriteLine("[Certificate] RSA Key Size:      {0} bits", (BkpCertInfo.subjectPublicKeyInfoRSAKey.ToByteArray().Length - 1) * 8);  //Substracted the sign (positive/negative) byte. More info: https://crypto.stackexchange.com/questions/30608/leading-00-in-rsa-public-private-key-file
            Console.WriteLine("[Certificate] Certificate Guid:  {0}", BkpCertInfo.asnCtx1CertGuid);

        }


        public static bool BkpCertInfoValidate(Interop.BACKUP_KEY_PUB_CERT_INFO BkpCertInfo, string domainName)
        {

            bool status = true;
            Console.WriteLine("\r\n[+] Validating Certificate format..."); // Validating the specific certificate requirements of the Backup key

            // There must be a better way than the below:
            if (BkpCertInfo.certSubjectStr.ToLower() != domainName.ToLower())
            {
                Console.WriteLine("  [!] ERROR: Subject should be identical to targeted Domain name");
                status = false;
            }

            if ((BkpCertInfo.subjectPublicKeyInfoRSAKey.ToByteArray().Length - 1) * 8 != BackupKeyBitLength)
            {
                Console.WriteLine("  [!] ERROR: Public key must be of 2048 bit in length");
                status = false;
            }

            if (BkpCertInfo.signatureAlgorithmOID != SignatureAlgOidOddballOIW)
            {
                Console.WriteLine("  [!] ERROR: Signature algorithm must be 1.3.14.3.2.29 Oddball OIW");
                status = false;
            }

            if (BkpCertInfo.certNotBefore.AddYears(CertificateValidityPeriodYears) != BkpCertInfo.certNotAfter)
            {
                Console.WriteLine("  [!] ERROR: Certificate validity should be 365 days");
                status = false;
            }

            if (BkpCertInfo.certVersionByte[0] != CertificateVersion)
            {
                Console.WriteLine("  [!] ERROR: Certificate version should be 3 (0x2)");
                status = false;
            }

            if (BkpCertInfo.asnCtx1CertGuid != BkpCertInfo.asnCtx2CertGuid)
            {
                Console.WriteLine("  [!] ERROR: Subject UniqueID and Issuer UniqueID should be identical");
                status = false;
            }

            if (BkpCertInfo.certIssuerStr != BkpCertInfo.certSubjectStr)
            {
                Console.WriteLine("  [!] ERROR: Issuer should be identical to Subject");
                status = false;
            }

            if (BkpCertInfo.certSerial.ToByteArray().Length != CertificateSerialNumberByteLen)
            {
                Console.WriteLine("  [!] ERROR: Serial number must be exactly 16 bytes in length");
                status = false;
            }
            return status;
        }


        public static X500DistinguishedName buildDNforBkp(string domainName)
        {

            // We have to make a trick to build a similar BackupKey certificate DN.
            // The standard way fails to recreate the same Microsoft's Backup key DN as the modern class creates
            // the PrintableString of the subject without Unicode encoding and without trailing null.
            // 
            // So we are going to build the DN as RAW a bytes array where we include the trailing null and encode it with Unicode.
            // The structure below will be place both to the Issuer and Subject

            // byte SEQUENCE (0x30)
            // byte SEQUENCE Length (0xXX) - length of set + sequence below
            //  byte SET (0x31)
            //  byte SET Length (0xXX) - length of seq below
            //      byte SEQUENCE (0x30)
            //      byte SEQUENCE Length (0xXX) - length of commoname Oid + Printable string Tag + domainNameUnicode
            //          byte Object Identifier (0x06) - Tag of Object identifier 
            //          byte Length of object identifier (0x03) - length of object id 
            //              byte[3] commonName (0x55 0x04 0x03) - 2.5.4.3 commonName (X.520 DN component)
            //          byte PrintableString (0x13) - Tag for printable string
            //          byte Length of PrintableString (0xXX) - length of domainNameUnicode
            //              byte[domainNameUnicode.Length] domainNameUnicode



            var domainNameForBkp = domainName + "\0";  // For some reason domain name, stored with trailing null
            var domainNameUnicode = Encoding.Convert(Encoding.Default, Encoding.Unicode, Encoding.Default.GetBytes(domainNameForBkp)); // Observed Backup key certificate DN encoded with Unicode.

            var dnRawLen = 6 + AsnCommonName.Length + 2 + domainNameUnicode.Length; // Sequence (2) + Set(2) + Sequence(2) + AsnCommonName (5) + Printablestring (2) + domainNameUnicode length
            byte[] dnRaw = new byte[dnRawLen];

            dnRaw[0] = AsnSeqTag; 
            dnRaw[1] = Convert.ToByte(dnRawLen - 2);
            dnRaw[2] = AsnSetTag; 
            dnRaw[3] = Convert.ToByte(dnRawLen - 4);
            dnRaw[4] = AsnSeqTag; 
            dnRaw[5] = Convert.ToByte(dnRawLen - 6);
            Array.Copy(AsnCommonName, 0, dnRaw, 6, AsnCommonName.Length);
            dnRaw[11] = AsnPrintableStringTag;
            dnRaw[12] = Convert.ToByte(domainNameUnicode.Length);
            Array.Copy(domainNameUnicode, 0, dnRaw, 13, domainNameUnicode.Length);
            X500DistinguishedName dnBuild = new X500DistinguishedName(dnRaw);

            return dnBuild;
        }

        public static byte[] pushGuidtoTbsCertificate(Guid guid, byte[] TbsCertificateBytes)
        {

            // Construct Context specific 1 & 2 ASN1 raw data
            byte[] GuidByte = guid.ToByteArray();
            byte[] certContextSpecific1 = new byte[19]; // certContextSpecific1 Tag + GuidLength (With Null) + Null + Guid Bytes
            certContextSpecific1[0] = AsnContextSpecific1Tag;
            certContextSpecific1[1] = AsnGuidLengthWithSign;
            certContextSpecific1[2] = AsnGuidByteSign;
            GuidByte.CopyTo(certContextSpecific1, 3);


            byte[] certContextSpecific2 = new byte[19]; // certContextSpecific2 Tag + GuidLength (With Null) + Null + Guid Bytes
            certContextSpecific2[0] = AsnContextSpecific2Tag;
            certContextSpecific2[1] = AsnGuidLengthWithSign;
            certContextSpecific2[2] = AsnGuidByteSign;
            GuidByte.CopyTo(certContextSpecific2, 3);



            // Transform Certificate to ASN, and navigate.
            var certASN = new AsnReader(TbsCertificateBytes, AsnEncodingRules.DER);
            var certMaintSeq = certASN.ReadSequence();
            var cert1stSeq = certMaintSeq.ReadSequence();

            // Create new ASN template
            AsnWriter asnW = new AsnWriter(AsnEncodingRules.DER);

            asnW.PushSequence();  // Open Main Sequence
            asnW.PushSequence();  // Open First Sequence

            for (int i = 0; i < 7; i++)
            {
                asnW.WriteEncodedValue(cert1stSeq.ReadEncodedValue().ToArray()); //  Rewriting existing 7 sequences
            }


            // Push GUID to Context Specfic 1 & 2
            asnW.WriteEncodedValue(certContextSpecific1);
            asnW.WriteEncodedValue(certContextSpecific2);

            asnW.PopSequence(); // Close First Sequence

            // Rewrite exising data on Main sequence
            asnW.WriteEncodedValue(certMaintSeq.ReadEncodedValue().ToArray());
            asnW.WriteEncodedValue(certMaintSeq.ReadEncodedValue().ToArray());
            asnW.PopSequence();  // Close Main Sequence


            var asnResult = asnW.Encode();
                        
            return asnResult;
        }

        public static Interop.DOMAIN_BACKUP_KEY ByteToDomainBackupKey(byte[] domainBackupKeyBytes)
        {
            //Inspired by: https://stackoverflow.com/questions/3278827/how-to-convert-a-structure-to-a-byte-array-in-c

            Interop.DOMAIN_BACKUP_KEY domainBackupKey = new Interop.DOMAIN_BACKUP_KEY();

            int size = Marshal.SizeOf(domainBackupKey);
            IntPtr ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.AllocHGlobal(size);
                Marshal.Copy(domainBackupKeyBytes, 0, ptr, size);
                domainBackupKey = (Interop.DOMAIN_BACKUP_KEY)Marshal.PtrToStructure(ptr, domainBackupKey.GetType());
                domainBackupKey.AllocBkpData(domainBackupKeyBytes, 
                                            Convert.ToInt32(domainBackupKey.cspLen), 
                                            Convert.ToInt32(domainBackupKey.certificateLength));

            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
            return domainBackupKey;
        }

        public static byte[] GetBackupKeyBytes(Interop.DOMAIN_BACKUP_KEY BackupKey)
        {

            // Calculate BackupKey size
            var domainBackupKeySize = (3 * 4) + BackupKey.cspLen + BackupKey.certificateLength; // 3 Header DWORDS + Csp + certificate


            // BackupKey Struct to Bytes
            //  There should be a better way to do that. Currently I fail to do it with Marshal.StructToPtr.

            //IntPtr dpapiBackupKeyPtr = Marshal.AllocHGlobal(Marshal.SizeOf(domainBackupKey));
            //Marshal.StructureToPtr(domainBackupKey, dpapiBackupKeyPtr, false);

            byte[] dpapiBackupKeyBytes = new byte[domainBackupKeySize];
            Array.Copy(BitConverter.GetBytes(BackupKey.bkpVersion), 0, dpapiBackupKeyBytes, 0, 4);
            Array.Copy(BitConverter.GetBytes(BackupKey.cspLen), 0, dpapiBackupKeyBytes, 4, 4);
            Array.Copy(BitConverter.GetBytes(BackupKey.certificateLength), 0, dpapiBackupKeyBytes, 8, 4);

            Marshal.Copy(BackupKey.cspBlobPtr, dpapiBackupKeyBytes, 12, (int)BackupKey.cspLen);
            Marshal.Copy(BackupKey.certificatePtr, dpapiBackupKeyBytes, 12 + (int)BackupKey.cspLen, (int)BackupKey.certificateLength);

            return dpapiBackupKeyBytes;
        }


        public static string dcToDomain(string DomainController)
        {
            // Assuming Domain Controller DNS address suffix is the domain name

            Match checkIfIP = Regex.Match(DomainController, @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");

            if (DomainController.Contains(".") && !checkIfIP.Success)
            {
                var domainNameStrArr = DomainController.Split('.')
                                                .Skip(1)
                                                .Take(DomainController.Length - 1)
                                                .ToArray();

                string domainName = string.Join(".", domainNameStrArr);

                return domainName;
            }
            else
            {
                Console.WriteLine("\r\n[!] ERROR: Domain Controller {0}, is not a full domain controller DNS name", DomainController);
                throw new InvalidOperationException("The provided domain controller is not a DNS name"); // We rely on the domain controller FQDN when we call this function.
                
            }

        }

        public static bool fileOutput(Guid GUID, byte[] outputBytes, string outputSuffix = ".dpapibkp")
        {
            string outputPrefix = "BACKUPKEY_";
            string OutputFilePath = outputPrefix + GUID.ToString() + outputSuffix;

            if (File.Exists(OutputFilePath))
            {
                Console.WriteLine("[!] ERROR: {0} already exists!", OutputFilePath);
                Console.WriteLine("[!] ERROR: Cannot write output to a file!");
                return false;
            }
            else
            {
                FileStream fs = File.Create(OutputFilePath);
                BinaryWriter bw = new BinaryWriter(fs);
                bw.Write(outputBytes);
                bw.Close();
                fs.Close();
                Console.WriteLine("[+] Written output to            : {0}", OutputFilePath);
                return true;
            }
        }

        public static Guid genBkpGuid()
        {
            // Since our Guid is going to be in the certificate serial number as well we have to align it with the x509 DER integer formatting.
            // Because the format interperet the serial number as a big endian, signed (Big) integer and requires it to be positive, it might prepend 0x00 byte to our serial number byte array - forcing it to be positive.
            // As the MS-BKRP protocol fails to fetch the public RSA from the DC when we have 17 byte serial, we have to make sure that the first byte in our serial number is under 0x80.
            // This will make the CertificateRequest keep the serial number with 16 bytes in length instead of prepending the sign byte.
            // Thus, because the serial number interpreted as a Big endian of the Guid, we must make sure that the Guid last byte is less than 0x80.
            // ***For some reason, the certificate included in many Backup keys we observed is negative, but without having this additional byte. Might be because they followed an older RFC.
            // Reference: https://stackoverflow.com/questions/55076109/why-does-certificaterequest-create-add-a-leading-zero-byte-to-the-serial-number
            // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2


            byte[] guidArr = new byte[16];
            int maxAttempts = 0;  // Need to stop this loop, mostly it will do under 10 iterations.
            do
            {
                using (RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create())
                {
                    randomNumberGenerator.GetBytes(guidArr);
                }
                maxAttempts++;
            }
            while ((guidArr[15] >= 0x80 || guidArr[15] == 0x00) && maxAttempts < 1000) ;
            


            Guid bkpGuid = new Guid(guidArr);


            if (bkpGuid.Equals(Guid.Empty) || maxAttempts >= 1000)
            {
                throw new InvalidOperationException("Error generating proper Guid, try repeating this operation");
            }

            return bkpGuid;

        }





        static void Main(string[] args)
        {
            IntPtr LsaPolicyHandle = IntPtr.Zero;
            IntPtr BackupKeyHandle = IntPtr.Zero;


            var parser = new Parser(s => 
            {
                s.AutoVersion = false;
                s.AutoHelp = true;
                s.HelpWriter = Console.Error;
            });

            
            var argParser = parser.ParseArguments<FetchBackupKeyCert_Opts,
                              GetBackupKey_Opts,
                              SetPreferredBackupKeyByGUID_Opts,
                              GenerateNewBackupKey_Opts,
                              CreateBackupKeyFromFile_Opts,
                              CheckBackupKey_Opts>
                              (args);

            try
            {



                int operation = argParser.MapResult(
                    (FetchBackupKeyCert_Opts opts) =>
                    {
                        byte[] msBkrpCert = GetMSBkrpServicedCert(opts.DomainController);
                        var msBkrpCertInfo = DecodeDERCertificate(msBkrpCert);
                        Console.WriteLine("[+] MS-BKRP Serviced Backupkey Guid         : {0}", msBkrpCertInfo.asnCtx1CertGuid.ToString());

                        if (opts.OutputFile)
                        {
                            fileOutput(msBkrpCertInfo.asnCtx1CertGuid, msBkrpCert, ".der");
                        }

                        if (opts.analyze)
                        {
                            BkpCertInfoPrint(msBkrpCertInfo);
                            string domainName = dcToDomain(opts.DomainController);
                            BkpCertInfoValidate(msBkrpCertInfo, domainName);
                        }
                        return 0;

                    },

                    (GetBackupKey_Opts opts) =>
                    {
                        Guid BackupKeyGUID = Guid.Empty;
                        LsaPolicyHandle = Initialize(opts.DomainController);
                        
                        if (String.IsNullOrEmpty(opts.GUID)) {
                            BackupKeyGUID = GetPreferredBackupGUID(LsaPolicyHandle);
                            Console.WriteLine("[+] Preferred backupkey Guid         : {0}", BackupKeyGUID.ToString());
                        }
                        else {
                            BackupKeyGUID = new Guid(opts.GUID);
                        }


                        byte[] backupKeyBytes = GetBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID);
                        var dpapiDomainBackupKey = GetBackupKeyFromBytes(backupKeyBytes);
                        byte[] BkpCertBytes = ExtractMSLsadBkpCertificate(dpapiDomainBackupKey);
                        var BkpCertInfo = DecodeDERCertificate(BkpCertBytes);

                        if (opts.analyze)
                        {
                            BkpCertInfoPrint(BkpCertInfo);
                            string domainName = dcToDomain(opts.DomainController);
                            BkpCertInfoValidate(BkpCertInfo, domainName);
                        }

                        if (opts.OutputFile)
                        {
                            fileOutput(BackupKeyGUID, backupKeyBytes);
                            fileOutput(BkpCertInfo.asnCtx1CertGuid, BkpCertBytes, ".der");
                        }

                        return 0;
                    },

                    (SetPreferredBackupKeyByGUID_Opts opts) =>
                    {
                        LsaPolicyHandle = Initialize(opts.DomainController);
                        Guid BackupKeyGUID = new Guid(opts.GUID);
                        if (GetBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID) != null)
                        {
                            SetPreferredBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID);
                        }
                        return 0;
                    },

                    (GenerateNewBackupKey_Opts opts) =>
                    {
                        Guid BackupKeyGUID = genBkpGuid();
                        Console.WriteLine("\r\n[+] Generated Guid: {0}", BackupKeyGUID);
                        Interop.DOMAIN_BACKUP_KEY BackupKey = GenerateDPAPIBackupKey(BackupKeyGUID, opts.DomainName);

                        byte[] BackupKeyBytes = GetBackupKeyBytes(BackupKey);
                        Console.WriteLine("[+] BackupKey size: {0}", BackupKeyBytes.Length);
                        byte[] BkpCertBytes = ExtractMSLsadBkpCertificate(BackupKey);
                        Interop.BACKUP_KEY_PUB_CERT_INFO BkpCertInfo = DecodeDERCertificate(BkpCertBytes);

                        BkpCertInfoPrint(BkpCertInfo);

                        if (BkpCertInfo.asnCtx1CertGuid.Equals(Guid.Empty) ||
                            !validateBackupKeyHeader(BackupKey) ||
                            !BkpCertInfoValidate(BkpCertInfo, opts.DomainName)
                            )
                        {
                            Console.WriteLine("\r\n[!] ERROR: Backup key generation failed!");
                            return 1;
                        }
                        BackupKey.FreePtrs(); // Customized Free for Csp ptr and Certificate Ptr


                        if (opts.OutputFile)
                        {
                            fileOutput(BkpCertInfo.asnCtx1CertGuid, BackupKeyBytes);
                            fileOutput(BkpCertInfo.asnCtx1CertGuid, BkpCertBytes, ".der");
                        }


                        if (opts.push)
                        {
                            if (String.IsNullOrEmpty(opts.DomainController))
                            { 
                                Console.WriteLine("\r\n[!] ERROR: You must provide Domain Controller to push to");
                                return 1;
                            }

                            if (opts.DomainName != dcToDomain(opts.DomainController))
                            {
                                Console.WriteLine("\r\n[!] ERROR: BackupKey Subject and Issuer must be identical to the targeted domain!");
                                return 1;
                            }

                            LsaPolicyHandle = Initialize(opts.DomainController);
                            BackupKeyHandle = CreateNewBackupKey(LsaPolicyHandle, BackupKeyGUID);
                            SetBackupKeyValue(BackupKeyHandle, BackupKeyBytes);
                            if (opts.set)
                            {
                                SetPreferredBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID);
                            }
                        }
                        return 0;
                    },

                    (CreateBackupKeyFromFile_Opts opts) =>
                    {
                        byte[] BackupKeyBytes = File.ReadAllBytes(opts.InputFile);
                        Console.WriteLine("[+] BackupKey size: {0}", BackupKeyBytes.Length);


                        var dpapiDomainBackupKey = GetBackupKeyFromBytes(BackupKeyBytes);
                        byte[] BkpCertBytes = ExtractMSLsadBkpCertificate(dpapiDomainBackupKey);
                        var BkpCertInfo = DecodeDERCertificate(BkpCertBytes);

                        // BackupKey structure validation
                        BkpCertInfoPrint(BkpCertInfo);                                                    

                        if (opts.push)
                        {
                            if (String.IsNullOrEmpty(opts.DomainController))
                            {
                                Console.WriteLine("\r\n[!] ERROR: You must provide Domain Controller to push to.");
                                return 1;

                            }

                            if (!BkpCertInfoValidate(BkpCertInfo, dcToDomain(opts.DomainController)) || BkpCertInfo.asnCtx1CertGuid == Guid.Empty)
                            {
                                Console.WriteLine("\r\n[!] ERROR: Input BackupKey file is invalid and/or was not generated for the targeted domain.");
                                return 1;
                            }
                            

                            LsaPolicyHandle = Initialize(opts.DomainController);
                            Console.WriteLine("\r\n[+] Checking that we will not overwrite exisitng backup key...");
                            BackupKeyHandle = GetBackupKeyHandleByGuid(LsaPolicyHandle, BkpCertInfo.asnCtx1CertGuid, true);
                            if (BackupKeyHandle != IntPtr.Zero)
                            {
                                Console.WriteLine("\r\n[!] ERROR: The backup key you are trying to push already exists.");
                                return 1;
                            }
                            BackupKeyHandle = CreateNewBackupKey(LsaPolicyHandle, BkpCertInfo.asnCtx1CertGuid);
                            SetBackupKeyValue(BackupKeyHandle, BackupKeyBytes);
                            if (opts.set)
                            {
                                SetPreferredBackupKeyByGUID(LsaPolicyHandle, BkpCertInfo.asnCtx1CertGuid);
                            }
                        }

                        return 0;
                    },

                    (CheckBackupKey_Opts opts) =>
                    {
                        LsaPolicyHandle = Initialize(opts.DomainController);
                        Guid currentPreferredGuid = GetPreferredBackupGUID(LsaPolicyHandle);
                        Console.WriteLine("[+] Preferred Backupkey Guid         : {0}\r\n", currentPreferredGuid.ToString());
                                                    
                        byte[] msBkrpCert = GetMSBkrpServicedCert(opts.DomainController);
                        var msBkrpCertInfo = DecodeDERCertificate(msBkrpCert);
                        Console.WriteLine("[+] MS-BKRP Serviced Backupkey Guid         : {0}", msBkrpCertInfo.asnCtx1CertGuid.ToString());


                        if (currentPreferredGuid == msBkrpCertInfo.asnCtx1CertGuid) {
                            Console.WriteLine("\r\n[+] SUCCESS! The serviced Backup Key (MS-BKRP) and the Preferred Backup key (MS-LSAD) are synced");
                        }
                        else {
                            Console.WriteLine("\r\n[!] ERROR: Expected serviced BackupKey Guid was not detected, try restarting the DC and repeat this check.");
                            return 1;
                        }

                        Console.WriteLine("\r\n[+] Validating MS-BKRP protocol health");
                        if (Interop.bkrp_test(opts.DomainController)) {
                            Console.WriteLine("\r\n[+] SUCCESS! MS-BKRP secret encryption & decryption passed!");
                        }
                        else {
                            Console.WriteLine("\r\n[!] MS-BKRP is unhealthy. Try reverting to the original backup key via SetPreferredBackupKey and restart the DC.");
                            return 1;
                        }

                        return 0;

                    },


                             
                    errors => 1);


                if (operation == 0) {
                    Console.WriteLine("\r\n[+] Operation completed successfully!");
                }

            }
            
            catch(Exception e) {
                Console.WriteLine("\r\n{0}", e);
            }
            
            finally {
                if (LsaPolicyHandle != IntPtr.Zero) {
                    Interop.LsaClose(LsaPolicyHandle);
                }
                
                if (BackupKeyHandle != IntPtr.Zero) {
                    Interop.LsaClose(BackupKeyHandle);
                }                
            }
            
        
        }
    }
}

