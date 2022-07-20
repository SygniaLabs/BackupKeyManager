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
        [Verb("GetPreferredBackupGUID", HelpText = "Extract the GUID of the preferred (current) backup key")]
        class GetPreferredBackupGUID_Opts
        {
          [Option('s', "DomainController", Required = true, HelpText = "Primary Domain Controller DNS Address to interact with")]
          public string DomainController { get; set; }
        }

        [Verb("GetPreferredBackupKey", HelpText = "Extract the preferred (current) backup key")]
        class GetPreferredBackupKey_Opts
        {
            [Option('s', "DomainController", Required = true, HelpText = "Primary Domain Controller DNS Address to interact with")]
            public string DomainController { get; set; }

            [Option('o', "OutputFile", Required = false, HelpText = "Dump Backupkey and certificate DER format outputs to files")]
            public bool OutputFile { get; set; }
            
            [Option("analyze", Required = false, HelpText = "Analyze the exported BackupKey")]
            public bool analyze { get; set; }
        }

        [Verb("GetBackupKeyByGUID", HelpText = "Extract a BackupKey value by GUID")]
        class GetBackupKeyByGUID_Opts
        {
            [Option('s', "DomainController", Required = true, HelpText = "Primary Domain Controller DNS Address to interact with")]
            public string DomainController { get; set; }

            [Option("GUID", Required = true, HelpText = "A GUID format string for the required action (e.g. XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)")]
            public string GUID { get; set; }

            [Option('o', "OutputFile", Required = false, HelpText = "Dump Backupkey and certificate DER format outputs to files")]
            public bool OutputFile { get; set; }
            
            [Option("analyze", Required = false, HelpText = "Analyze the exported BackupKey")]
            public bool analyze { get; set; }
        }

        [Verb("SetPreferredBackupKeyByGUID", HelpText = "Set a new preferred bakupkey by providing its GUID")]
        class SetPreferredBackupKeyByGUID_Opts
        {
            [Option('s', "DomainController", Required = true, HelpText = "Primary Domain Controller DNS Address to interact with")]
            public string DomainController { get; set; }

            [Option("GUID", Required = true, HelpText = "A GUID format string for the required action (e.g. XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)")]
            public string GUID { get; set; }
        }

        [Verb("GenerateNewBackupKey", HelpText = "Generate GUID and new backup key with option to push and set as preferred.")]
        class GenerateNewBackupKey_Opts
        {
            [Option('d', "DomainName", Required = true, HelpText = "FQDN of the required domain. This will be included in the public certificate.")]
            public string DomainName { get; set; }

            [Option('o', "OutputFile", Required = false, HelpText = "Dump Backupkey and certificate DER format outputs to files")]
            public bool OutputFile { get; set; }

            [Option('s', "DomainController", Required = false, HelpText = "Primary Domain Controller DNS Address to interact with. Set this this value if you wish to use push")]
            public string DomainController { get; set; }
           
            [Option("push", Required = false, HelpText = "Push the generated backup key to the Domain Controller.")]
            public bool push { get; set; }
            
            [Option("set", Required = false, HelpText = "Set the generated backup key as the Preferred Backupkey. --push must be used as well.")]
            public bool set { get; set; }
        }

        [Verb("PushBackupKeyFromFile", HelpText = "Push new backup key from file. InputFile is required.")]
        class CreateBackupKeyFromFile_Opts
        {
            [Option('s', "DomainController", Required = true, HelpText = "Primary Domain Controller DNS Address to interact with")]
            public string DomainController { get; set; }

            [Option('i', "InputFile", Required = true, HelpText = "Backup key input file in the dumped/created format - dpapibackupkey")]
            public string InputFile { get; set; }

            [Option("set", Required = false, HelpText = "Set the imported backup key as the Preferred Backupkey.")]
            public bool set { get; set; }
        }




        public static bool checkNTstatus(uint ntStatus, string calledFunction, bool continueOnError = false)
        {

            if (ntStatus != 0)
            {
                uint winErrorCode = Interop.LsaNtStatusToWinError(ntStatus);
                string errorMessage = new Win32Exception((int)winErrorCode).Message;
                Console.WriteLine("  [!] Error calling {0} {1} : {2}", calledFunction, winErrorCode, errorMessage);
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


            Guid backupKeyGuid = new Guid(guidBytes);
            Console.WriteLine("[+] Preferred backupkey Guid         : {0}", backupKeyGuid);


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

            return;

        }

        public static byte[] GetBackupKeyByGUID(IntPtr LsaPolicyHandle, Guid backupKeyGuid, string DomainController = "", bool analyze = false, bool outFile = false)
        {
                       
            string backupKeyName = String.Format("G$BCKUPKEY_{0}", backupKeyGuid.ToString());
            Console.WriteLine("[+] Getting backup key     : {0}", backupKeyName);
            
            Interop.LSA_UNICODE_STRING backupKeyLSA = new Interop.LSA_UNICODE_STRING(backupKeyName);

            // retrieve the bytes of the full DPAPI private backup key
            uint ntsResult = Interop.LsaRetrievePrivateData(LsaPolicyHandle, ref backupKeyLSA, out IntPtr PrivateData);
            
            checkNTstatus(ntsResult, "LsaRetrievePrivateData");

            Interop.LSA_UNICODE_STRING backupKeyBytesLSA = (Interop.LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateData, typeof(Interop.LSA_UNICODE_STRING));
            Marshal.FreeHGlobal(PrivateData);


            byte[] backupKeyBytes = new byte[backupKeyBytesLSA.Length];
            Marshal.Copy(backupKeyBytesLSA.buffer, backupKeyBytes, 0, backupKeyBytesLSA.Length);


            if (analyze)
            {
                string domainName = dcToDomain(DomainController);
                var dpapiDomainBackupKey = analyzeBackupKeyBytes(backupKeyBytes);
                analyzeBkpCertificate(dpapiDomainBackupKey, domainName, outFile);
            }

            if (outFile)
            {
                fileOutput(backupKeyGuid, backupKeyBytes);
            }

            return backupKeyBytes;
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
            Console.WriteLine("[+] New Backup Key to be created     : {0}", NewBackupKeyName);
            Interop.LSA_UNICODE_STRING NewBackupKeyNameLSA = new Interop.LSA_UNICODE_STRING(NewBackupKeyName);


            uint ntsResult = Interop.LsaCreateSecret(LsaPolicyHandle, ref NewBackupKeyNameLSA, (uint)Interop.LSA_AccessPolicy.POLICY_CREATE_SECRET, out IntPtr NewBackupKeySecretHandle);

            checkNTstatus(ntsResult, "LsaCreateSecret");

            Console.WriteLine("[+] New Backup Key created successfully     : {0}", NewBackupKeyName);
            return NewBackupKeySecretHandle;
        }

        public static void SetBackupKeyValue(IntPtr BackupKeyHandle, byte[] BackupKeyValueByte)
        {

            string BackupKeyValueStr = System.Text.Encoding.Unicode.GetString(BackupKeyValueByte);
            Interop.LSA_UNICODE_STRING BackupKeyValueStrLSA = new Interop.LSA_UNICODE_STRING(BackupKeyValueStr);

            //IntPtr BackupKeyValueStrLSAPointer = Marshal.AllocHGlobal(Marshal.SizeOf(BackupKeyValueStrLSA));
            //Marshal.StructureToPtr(BackupKeyValueStrLSA, BackupKeyValueStrLSAPointer, false);

            Console.WriteLine("[+] Setting BackupKey value...");
            uint ntsResult = Interop.LsaSetSecret(BackupKeyHandle, ref BackupKeyValueStrLSA, ref BackupKeyValueStrLSA);

            checkNTstatus(ntsResult, "LsaSetSecret");

            Console.WriteLine("[+] BackupKey value was set successfully!");
            return;  

        }

        public static byte[] GenerateDPAPIBackupKey(Guid backupKeyGuid, string domainName, bool outFile = false)
        {

            byte[] GuidByte = backupKeyGuid.ToByteArray();
            
            
            Console.WriteLine("\r\n[+] Generating 2048 bit RSA Key pair...");
            
            int keyLen = 2048;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keyLen);
            var cspBlob = rsa.ExportCspBlob(true);            
          

            
            Console.WriteLine("[+] Creating certificate"); // Accoridng to MS-BKRP [2.2.1] specification
            
            byte[] certSerial = GuidByte.Reverse().ToArray();  // Certificate Serial
            var dn = buildDNforBkp(domainName);                // Certificate Distinguished Name
            Helpers.RSASha1Pkcs1SignatureGenerator generator = new Helpers.RSASha1Pkcs1SignatureGenerator(rsa);          
            var certRequest = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);           
            var certificate = certRequest.Create(dn, generator, DateTime.UtcNow, DateTime.UtcNow.AddYears(1), certSerial);
            var certBytes = certificate.Export(X509ContentType.Cert);
            var certBytesWithGuid = pushGuidtoTbsCertificate(backupKeyGuid, certBytes);  // Appending key Guid to  issuerUniqueID &  subjectUniqueID slots



            Console.WriteLine("[+] Building the new Domain BackupKey..."); // Accoridng to MS-BKRP [2.2.5] specification

            Interop.DOMAIN_BACKUP_KEY domainBackupKey = new Interop.DOMAIN_BACKUP_KEY();

            // Calculate BackupKey size
            var domainBackupKeySize = (3 * 4) + cspBlob.Length + certBytesWithGuid.Length; // 3 Header DWORDS + Csp + certificate

            // Set the headers (UINT type)
            domainBackupKey.bkpVersion = (uint)2;
            domainBackupKey.cspLen = Convert.ToUInt32(cspBlob.Length);
            domainBackupKey.certificateLength = Convert.ToUInt32(certBytesWithGuid.Length);

            
            // Allocate pointers for Csp and Certificate
            domainBackupKey.AllocKeyData(cspBlob, certBytesWithGuid);

                       
            if (analyzeBkpCertificate(domainBackupKey, domainName, outFile) == Guid.Empty &&
                !validateBackupKeyHeader(domainBackupKey)
                )
            {
                return null;
            }



            // BackupKey Struct to Bytes
            //  There should be a better way to do that. Currently I fail to do it with Marshal.StructToPtr.

            byte[] dpapiBackupKeyBytes = new byte[domainBackupKeySize];
            Array.Copy(BitConverter.GetBytes(domainBackupKey.bkpVersion), 0, dpapiBackupKeyBytes, 0, 4);
            Array.Copy(BitConverter.GetBytes(domainBackupKey.cspLen), 0, dpapiBackupKeyBytes, 4, 4);
            Array.Copy(BitConverter.GetBytes(domainBackupKey.certificateLength), 0, dpapiBackupKeyBytes, 8, 4);

            Marshal.Copy(domainBackupKey.cspBlobPtr, dpapiBackupKeyBytes, 12, cspBlob.Length);
            Marshal.Copy(domainBackupKey.certificatePtr, dpapiBackupKeyBytes, 12+cspBlob.Length, certBytesWithGuid.Length);

            
            domainBackupKey.FreePtrs(); // Customized Free for Csp ptr and Certificate Ptr


            if (outFile)
            {
                fileOutput(backupKeyGuid, dpapiBackupKeyBytes);
            }

            return dpapiBackupKeyBytes;
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

        public static Interop.DOMAIN_BACKUP_KEY analyzeBackupKeyBytes(byte[] dpapiDomainBackupBytes)
        {

            Console.WriteLine("[+] BackupKey size: {0}", dpapiDomainBackupBytes.Length);
            Interop.DOMAIN_BACKUP_KEY dpapiDomainBackupKey = ByteToDomainBackupKey(dpapiDomainBackupBytes);

            if (!validateBackupKeyHeader(dpapiDomainBackupKey))
            {
                Console.WriteLine("[!] ERROR: BackupKey input is invalid or corrupted.");
;                return dpapiDomainBackupKey;
            }


            return dpapiDomainBackupKey;
        }

        public static bool validateBackupKeyHeader(Interop.DOMAIN_BACKUP_KEY dpapiBackupKey)
        {

            Console.WriteLine("\r\n[+] Validating BackupKey header...");
            //Header validations:
            if (dpapiBackupKey.bkpVersion == 2 &&   // 02 00 00 00
                 dpapiBackupKey.cspLen == 1172 &&     // 94 04 00 00  - This will make sure we choose 2048 bit key.
                 dpapiBackupKey.certificateLength > 0
                 )
            {
                return true;
            }
            Console.WriteLine("[!] ERROR: BackupKey validation failed!");
            return false;
        }

        public static Guid analyzeBkpCertificate(Interop.DOMAIN_BACKUP_KEY dpapiDomainBackupKey, string domainName, bool outFile = false)
        {

            // Extract Certificate from BackupKey structure
            int certificateSize = Convert.ToInt32(dpapiDomainBackupKey.certificateLength);
            byte[] certificateDERformat = new byte[certificateSize];
            Marshal.Copy(dpapiDomainBackupKey.certificatePtr, certificateDERformat, 0, certificateSize);



            Console.WriteLine("\r\n[+] Analyzing certificate information:");
            var certASN = new AsnReader(certificateDERformat, AsnEncodingRules.DER);

            Console.WriteLine("[ASN] - {0}: {1}", certASN.PeekTag(), certASN.PeekContentBytes().Length);
            var seq3 = new AsnReader(certASN.PeekContentBytes(), AsnEncodingRules.DER);
            var seq9 = new AsnReader(seq3.PeekContentBytes(), AsnEncodingRules.DER);
            Console.WriteLine("[ASN]  - {0}: {1}", seq3.PeekTag(), seq3.PeekContentBytes().Length);

            var certVersionEncoded = seq9.ReadEncodedValue();
            byte[] certVersionByte = certVersionEncoded.ToArray().Skip(4).Take(1).ToArray(); // Version 3, should be 02.

            var certSerial = seq9.ReadInteger(); // CertificateSerialNumber (Bigint)

            var signatureAlgorithmOID = seq9.ReadSequence().ReadObjectIdentifier();  //OID 1.3.14.3.2.29 sha-1WithRSAEncryption (Oddball OIW OID)


            var certIssuer = seq9.ReadSequence().ReadSetOf().ReadSequence();  // Issuer
            certIssuer.ReadObjectIdentifier(); // 2.5.4.3 commonName (X.520 DN component)
            var certIssuerEncValue = certIssuer.ReadEncodedValue(); //PrintableString of CommonName. Exception on while trying to ReadCharacterString.
            string certIssuerStr = Encoding.Default.GetString(certIssuerEncValue.ToArray().Skip(2).ToArray());
            certIssuerStr = certIssuerStr.Replace("\0", string.Empty);  // Issuer is stored as a UTF16 LE.


            var validDates = seq9.ReadSequence();  // Cert validity
            var certNotBefore = validDates.ReadUtcTime(); // Not before UTC time
            var certNotAfter = validDates.ReadUtcTime();  // Not after UTC time



            var certSubject = seq9.ReadSequence().ReadSetOf().ReadSequence(); //Subject
            certSubject.ReadObjectIdentifier();  // 2.5.4.3 commonName (X.520 DN component)
            var certSubjectEncValue = certSubject.ReadEncodedValue(); //PrintableString of CommonName 
            string certSubjectStr = Encoding.Default.GetString(certSubjectEncValue.ToArray().Skip(2).ToArray());
            certSubjectStr = certSubjectStr.Replace("\0", string.Empty);  // Subject is stored as a UTF16 LE.


            var subjectPublicKeyInfo = seq9.ReadSequence(); // subjectPublicKeyInfo
            var subjectPublicKeyInfoOID = subjectPublicKeyInfo.ReadSequence().ReadObjectIdentifier(); // subjectPublicKeyInfo - OID 1.2.840.113549.1.1.1 
            byte[] subjectPublicKeyInfoBitStr = subjectPublicKeyInfo.ReadBitString(out int unusedarg);
            var subjectPublicKeyInfoBitStrReader = new AsnReader(subjectPublicKeyInfoBitStr, AsnEncodingRules.DER);
            var subjectPublicKeyInfoRSAKey = subjectPublicKeyInfoBitStrReader.ReadSequence().ReadInteger();



            var issuerUniqueIDEncoded = seq9.ReadEncodedValue(); // BackupKey encoded GUID 
            var subjectUniqueIDEncoded = seq9.ReadEncodedValue(); // BackupKey encoded GUID 
            seq9.ThrowIfNotEmpty();


            seq3.ReadSequence();
            Console.WriteLine("[ASN]  - {0}: {1}", seq3.PeekTag(), seq3.PeekContentBytes().Length);
            seq3.ReadSequence();
            Console.WriteLine("[ASN]  - {0}: {1}", seq3.PeekTag(), seq3.PeekContentBytes().Length);
            seq3.ReadBitString(out int countof3BitStr);
            seq3.ThrowIfNotEmpty();

            // Closing the reader and throw exception if we missed somthing.
            certASN.ReadSequence();
            certASN.ThrowIfNotEmpty();


            byte[] CertGuidByte1 = subjectUniqueIDEncoded.ToArray().Skip(3).Take(16).ToArray(); // Transfrom from ASN1 encoded representation to Guid Bytes.
            byte[] CertGuidByte2 = issuerUniqueIDEncoded.ToArray().Skip(3).Take(16).ToArray();

            Guid bkpCertGuid = new Guid(CertGuidByte1);



            Console.WriteLine("[Certificate] Serial Number:     {0}", BitConverter.ToString(certSerial.ToByteArray()));
            Console.WriteLine("[Certificate] Version:           {0}", ((int)certVersionByte[0]) + 1); // Adding 1 to reflect the actual version.
            Console.WriteLine("[Certificate] Issuer name:       {0}", certIssuerStr);
            Console.WriteLine("[Certificate] Subject name:      {0}", certSubjectStr);
            Console.WriteLine("[Certificate] Not Before:        {0}", certNotBefore);
            Console.WriteLine("[Certificate] Not After:         {0}", certNotAfter);
            Console.WriteLine("[Certificate] Validity period:   {0}", certNotAfter - certNotBefore);
            Console.WriteLine("[Certificate] SignatureAlgo OID: {0}", signatureAlgorithmOID);
            Console.WriteLine("[Certificate] PublicKeyInfo OID: {0}", subjectPublicKeyInfoOID);
            Console.WriteLine("[Certificate] RSA Key Size:      {0} bits", (subjectPublicKeyInfoRSAKey.ToByteArray().Length - 1) * 8);  //Substracted the sign (positive/negative) byte. More info: https://crypto.stackexchange.com/questions/30608/leading-00-in-rsa-public-private-key-file
            Console.WriteLine("[Certificate] Certificate Guid:  {0}", bkpCertGuid);

            if (outFile)
            {
                fileOutput(bkpCertGuid, certificateDERformat, ".der");
            }

            
            Console.WriteLine("\r\n[+] Validating certificate format");

            int certValidationsNum = 7;
            String[] certError = new string[certValidationsNum];
            if (certSubjectStr.ToLower() != domainName.ToLower()) { certError[0] = "Subject should be identical to targeted Domain name"; }
            else if ((subjectPublicKeyInfoRSAKey.ToByteArray().Length - 1) * 8 != 2048) { certError[1] = "Public key must be of 2048 bit in length"; }
            else if (signatureAlgorithmOID != "1.3.14.3.2.29") { certError[2] = "Signature algorithm must be 1.3.14.3.2.29 Oddball OIW"; }
            else if (certNotBefore.AddYears(1) != certNotAfter) { certError[3] = "Certificate validity should be 365 days"; }
            else if (certVersionByte[0] != 0x2) { certError[4] = "Certificate version should be 3 (0x2)"; }
            else if (!CertGuidByte1.SequenceEqual(CertGuidByte2)) { certError[5] = "Subject UniqueID and Issuer UniqueID should be identical"; }
            else if (certIssuerStr != certSubjectStr) { certError[6] = "Issuer should be identical to Subject"; }

            for (int i = 0; i < certValidationsNum; i++)
            {
                if (certError[i] != null)
                {
                    Console.WriteLine("[!] ERROR: Certificate format validation failed!");
                    foreach (var errMsg in certError)
                    {
                        Console.WriteLine("    [!] {0}", errMsg);
                        return Guid.Empty;
                    }
                }
            }
            
            return bkpCertGuid;
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


            var domainNameForBkp = domainName + "\0";  // For some reaso domain name, stored with trailing null
            var domainNameUnicode = Encoding.Convert(Encoding.Default, Encoding.Unicode, Encoding.Default.GetBytes(domainNameForBkp)); // Observed Backup key certificate DN encoded with Unicode.

            byte[] cnAsn = { 0x06, 0x03, 0x55, 0x04, 0x03 }; // ASN Bytes for commonName


            var dnRawLen = 6 + cnAsn.Length + 2 + domainNameUnicode.Length; // Sequence (2) + Set(2) + Sequence(2) + CNAsn (5) + Printablestring (2) + domainNameUnicode length
            byte[] dnRaw = new byte[dnRawLen];

            dnRaw[0] = 0x30; //Asn tag for Sequence
            dnRaw[1] = Convert.ToByte(dnRawLen - 2);
            dnRaw[2] = 0x31; // Asn tag for SET
            dnRaw[3] = Convert.ToByte(dnRawLen - 4);
            dnRaw[4] = 0x30; //Asn tag for Sequence
            dnRaw[5] = Convert.ToByte(dnRawLen - 6);
            Array.Copy(cnAsn, 0, dnRaw, 6, cnAsn.Length);
            dnRaw[11] = 0x13; // Asn tag for PrintableString
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
            certContextSpecific1[0] = 0x81;
            certContextSpecific1[1] = 0x11;
            certContextSpecific1[2] = 0x00;
            GuidByte.CopyTo(certContextSpecific1, 3);


            byte[] certContextSpecific2 = new byte[19]; // certContextSpecific2 Tag + GuidLength (With Null) + Null + Guid Bytes
            certContextSpecific2[0] = 0x82;
            certContextSpecific2[1] = 0x11;
            certContextSpecific2[2] = 0x00;
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

        public static bool fileOutput(Guid GUID, byte[] outputBytes, string outputSuffix = ".dpapibck.key")
        {
            string outputPrefix = "BACKUPKEY_";
            string OutputFilePath = outputPrefix + GUID.ToString() + outputSuffix;

            if (File.Exists(OutputFilePath))
            {
                Console.WriteLine("[!] ERROR: The output path already exists!");
                Console.WriteLine("[!] ERROR: Can't write output to a file!");
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


        static void Main(string[] args)
        {


            Parser.Default.ParseArguments<GetPreferredBackupGUID_Opts,
                                          GetPreferredBackupKey_Opts,
                                          GetBackupKeyByGUID_Opts,
                                          SetPreferredBackupKeyByGUID_Opts,
                                          GenerateNewBackupKey_Opts,
                                          CreateBackupKeyFromFile_Opts>
                                          (args)
                                          .MapResult(
                                            (GetPreferredBackupGUID_Opts opts) => {
                                                IntPtr LsaPolicyHandle = Initialize(opts.DomainController);
                                                GetPreferredBackupGUID(LsaPolicyHandle).ToString();
                                                Interop.LsaClose(LsaPolicyHandle);
                                                return 0; 
                                                },
                                           
                                            (GetPreferredBackupKey_Opts opts) => {
                                                IntPtr LsaPolicyHandle = Initialize(opts.DomainController);
                                                Guid preferredBackupKeyGUID = GetPreferredBackupGUID(LsaPolicyHandle);
                                                GetBackupKeyByGUID(LsaPolicyHandle, preferredBackupKeyGUID, 
                                                                   opts.DomainController, opts.analyze, opts.OutputFile);
                                                Interop.LsaClose(LsaPolicyHandle);
                                                return 0; 
                                            },
                                            
                                            (GetBackupKeyByGUID_Opts opts) => {
                                                IntPtr LsaPolicyHandle = Initialize(opts.DomainController);
                                                Guid BackupKeyGUID = new Guid(opts.GUID);
                                                GetBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID, 
                                                                   opts.DomainController, opts.analyze, opts.OutputFile);
                                                Interop.LsaClose(LsaPolicyHandle);
                                                return 0; 
                                            },
                                            
                                            (SetPreferredBackupKeyByGUID_Opts opts) => {
                                                IntPtr LsaPolicyHandle = Initialize(opts.DomainController);
                                                Guid BackupKeyGUID = new Guid(opts.GUID);
                                            if (GetBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID) != null )
                                                {
                                                    SetPreferredBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID);
                                                }
                                                Interop.LsaClose(LsaPolicyHandle);
                                                return 0; 
                                            },
                                            
                                            (GenerateNewBackupKey_Opts opts) => {

                                                Guid BackupKeyGUID = Guid.NewGuid();
                                                Console.WriteLine("\r\n[+] Generated Guid: {0}", BackupKeyGUID);
                                                byte[] BackupKeyBytes = GenerateDPAPIBackupKey(BackupKeyGUID, opts.DomainName, opts.OutputFile);
                                                if (BackupKeyBytes == null)
                                                {
                                                    Console.WriteLine("[!] ERROR: BackupKey generation failed.");
                                                    return 1;
                                                }    
                                                if (opts.push)
                                                {
                                                    if (String.IsNullOrEmpty(opts.DomainController))
                                                    { throw new ArgumentException("You must provide Domain Controller to push to"); }
                                                    IntPtr LsaPolicyHandle = Initialize(opts.DomainController);
                                                    IntPtr BackupKeyHandle = IntPtr.Zero;
                                                    BackupKeyHandle = CreateNewBackupKey(LsaPolicyHandle, BackupKeyGUID);
                                                    SetBackupKeyValue(BackupKeyHandle, BackupKeyBytes);
                                                    Interop.LsaClose(BackupKeyHandle);
                                                    if (opts.set)
                                                    {
                                                        SetPreferredBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID);
                                                    }
                                                    Interop.LsaClose(LsaPolicyHandle);
                                                }
                                                return 0;
                                            },
                                            
                                            (CreateBackupKeyFromFile_Opts opts) => {
                                                byte[] BackupKeyBytes = File.ReadAllBytes(opts.InputFile);
                                                var dpapiDomainBackupKey = analyzeBackupKeyBytes(BackupKeyBytes);                                            
                                                string domainName = dcToDomain(opts.DomainController); // Given the DC's DNS name and not IP / name only!
                                                Guid BackupKeyGUID = analyzeBkpCertificate(dpapiDomainBackupKey, domainName);
                                                if (BackupKeyGUID == Guid.Empty)
                                                {
                                                    return 1;
                                                }
                                                IntPtr LsaPolicyHandle = Initialize(opts.DomainController);
                                                Console.WriteLine("\r\n[+] Checking that we will not overwrite exisitng backup key...");
                                                IntPtr BackupKeyHandle = IntPtr.Zero;
                                                BackupKeyHandle = GetBackupKeyHandleByGuid(LsaPolicyHandle, BackupKeyGUID, true);
                                                if (BackupKeyHandle != IntPtr.Zero)
                                                {
                                                    throw new ArgumentException("The backup key you are trying to push already exists.");
                                                }
                                                BackupKeyHandle = CreateNewBackupKey(LsaPolicyHandle, BackupKeyGUID);
                                                SetBackupKeyValue(BackupKeyHandle, BackupKeyBytes);
                                                if (opts.set)
                                                  {
                                                     SetPreferredBackupKeyByGUID(LsaPolicyHandle, BackupKeyGUID);
                                                  }
                                                Interop.LsaClose(BackupKeyHandle);
                                                Interop.LsaClose(LsaPolicyHandle);
             
                                                return 0;
                                            },
                                            errors => 1);

            Console.WriteLine("\r\n[+] Operation completed successfully!");
        }

    
    }
}

