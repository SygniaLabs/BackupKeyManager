using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BackupKeyManager
{

    public static class Helpers
    {

        public sealed class RSASha1Pkcs1SignatureGenerator : X509SignatureGenerator
        {
            private readonly X509SignatureGenerator _realRsaGenerator;

            internal RSASha1Pkcs1SignatureGenerator(RSA rsa)
            {
                _realRsaGenerator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
            }

            protected override PublicKey BuildPublicKey() => _realRsaGenerator.PublicKey;

            public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
            {
                if (hashAlgorithm == HashAlgorithmName.SHA1)
                    return ConvertHexStringToByteArray("300906052B0E03021D0500"); //  1.3.14.3.2.29 Oddball OIW
                    //return ConvertHexStringToByteArray("300D06092A864886F70D0101050500");
                

                throw new InvalidOperationException();
            }

            public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) =>
                _realRsaGenerator.SignData(data, hashAlgorithm);
        }

        public static byte[] ConvertHexStringToByteArray(string hexString)
        {
            if (hexString.Length % 2 != 0)
            {
                //throw new ArgumentException(String.Format("The binary key cannot have an odd number of digits: {0}", hexString));
                hexString = "0" + hexString;
            }

            byte[] HexAsBytes = new byte[hexString.Length / 2];
            for (int index = 0; index < HexAsBytes.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                HexAsBytes[index] = byte.Parse(byteValue, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
            }

            return HexAsBytes;
        }

        public static void LogLine(String Type, String Message, bool PrependNewLine = false)
        {           
            if (PrependNewLine)
            {
                Console.WriteLine("");
            }
            switch (Type)
            {
                case "SUCCESS":
                    Console.WriteLine("[+] {0}", Message);
                        break;
                case "INFO":
                    Console.WriteLine("[-] {0}", Message);
                    break;
                case "ERROR":
                    Console.WriteLine("[!] ERROR: {0}", Message);
                        break;
                case "DEBUG":
                    Console.WriteLine("[*] {0}", Message);
                        break;
                case "ACTION":
                    Console.WriteLine("[?] {0}", Message);
                    break;
                case "CERTINFO":
                    Console.WriteLine("[Certificate] {0}", Message);
                    break;
                default:
                    break;

                }
        }

    }
}