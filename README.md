# DPAPI BackupKeyManager

## Overview

Data Protection API (DPAPI), is a widely used fucntionality within Windows applications to encrpyt sensitive data without taking care the encryption itself.<br />
Every Windows user has a Master Key (located in his profile path) that he uses to encrypt and decrypt data which can be stored locally or remotely.<br />
For Active Directory users, one copy of this Master Key is encrypted with the user's password and another copy is encrypted with the Domain BackupKey.
The second encrpytion was desgined to help users recover encrypted secrets in case they forget their own password.<br />
The Domain BackupKey is a unique RSA key pair generated during the Active Directory domain inception.
Due to the fact that the BackupKey is permanent per domain, an exposure of this key provides an adversary with the ability to decrypt users' Master keys across the domain indefinitely.<br />

The [BackupKeyManager]() is a tool to help organizations enhance their security, on a post compromise scenario, where their DPAPI Domain BackupKey was exposed and they wish to mitigate the risk of further exploitation with this key.
It is simply done by generating a new BackupKey and onboard existing users' to backup their Master Keys with the new BackupKey.

For more information and the research behind this tool you can visit our blogpost -> [The downfall of DPAPI's top-secret weapon]()


## Usage

This repository contains three projects:
* BackupKeyManager - The main Backup Key modification tool (C#)
* bkrp_test - A utility to check that your backup key is healthy (C)
* user-key-onboarding - A utility to onboard existing AD users to the domain backup key (PS)

### Create and onboard new DPAPI Backup key flow:

1. First, you will have to use the BackupKeyManager to create and prefer a new backup key in the domain (Write down the generated GUID).
2. A restart will be required to the DC as we must reload the LSASS process.
3. Use the bkrp_test and verify that the certificate's GUID being served is identical to the one generated during step #1.
4. From a domain user context, execute the user-key-onboarding with either the soft or forced method. Note which user Master keys are using the new backup key (Compare GUID).
5. Repeat step #4 for every user you would like to onboard to the new key.




## BackupKeyManager

The BackupKeyManager tool provides information on what and how you can use it.
There are few verbs alongside with specific flags you can set according to your needs.

### List verbs:

```
C:\BackupKeyManager>BackupKeyManager.exe --help
BackupKeyManager 1.0.0.0
Copyright c  2022

  GetPreferredBackupGUID         Extract the GUID of the preferred (current) backup key

  GetPreferredBackupKey          Extract the preferred (current) backup key

  GetBackupKeyByGUID             Extract a BackupKey value by GUID

  SetPreferredBackupKeyByGUID    Set a new preferred bakupkey by providing its GUID

  GenerateNewBackupKey           Generate GUID and new backup key with option to push and set as preferred.

  PushBackupKeyFromFile          Push new backup key from file. InputFile is required.

  help                           Display more information on a specific command.

  version                        Display version information.

```

### List specific verb's flags:

```
C:\BackupKeyManager>BackupKeyManager.exe GenerateNewBackupKey --help
BackupKeyManager 1.0.0.0
Copyright c  2022

  -d, --DomainName          Required. FQDN of the required domain. This will be included in the public key part.

  -o, --OutputFile          Dump Backupkey and certificate DER format outputs to files

  -s, --DomainController    Primary Domain Controller DNS Address to interact with. Set this this value if you wish to
                            use push

  --push                    Push the generated backup key to the Domain Controller.

  --set                     Set the generated backup key as the Preferred Backupkey. --push must be used as well.

  --help                    Display this help screen.

  --version                 Display version information.
```


### Get information about the currently active (preferred) BackupKey:

```
C:\BackupKeyManager>BackupKeyManager.exe GetPreferredBackupKey -s dc.thedomain.local --analyze

[+] Setting up connection with Domain Controller: dc.thedomain.local
[+] Getting backup key     : G$BCKUPKEY_8de8723b-8609-4bd0-89c3-55c512949356
[+] BackupKey size: 1952

[+] Validating BackupKey header...

[+] Analyzing certificate information:
[ASN] - Constructed SequenceOf: 764
[ASN]  - Constructed SequenceOf: 488
[ASN]  - Constructed SequenceOf: 9
[ASN]  - BitString: 257
[Certificate] Serial Number:     3B-72-E8-8D-09-86-D0-4B-89-C3-55-C5-12-94-93-56
[Certificate] Version:           3
[Certificate] Issuer name:       thedomain.local
[Certificate] Subject name:      thedomain.local
[Certificate] Not Before:        7/8/2022 7:07:34 AM +00:00
[Certificate] Not After:         7/8/2023 7:07:34 AM +00:00
[Certificate] Validity period:   365.00:00:00
[Certificate] SignatureAlgo OID: 1.3.14.3.2.29
[Certificate] PublicKeyInfo OID: 1.2.840.113549.1.1.1
[Certificate] RSA Key Size:      2048 bits
[Certificate] Certificate Guid:  8de8723b-8609-4bd0-89c3-55c512949356

[+] Validating certificate format

```

### Generate new BackupKey and use it as the preferred BackupKey :

```
C:\BackupKeyManager>BackupKeyManager.exe GenerateNewBackupKey -d thedomain.local -s dc.thedomain.local --set --push

[+] Generated Guid: d799cd2d-8ac2-4242-aa5b-697eb6d4a613

[+] Generating 2048 bit RSA Key pair...
[+] Creating certificate
[+] Building the new Domain BackupKey...

[+] Analyzing certificate information:
[ASN] - Constructed SequenceOf: 764
[ASN]  - Constructed SequenceOf: 488
[ASN]  - Constructed SequenceOf: 9
[ASN]  - BitString: 257
[Certificate] Serial Number:     2D-CD-99-D7-C2-8A-42-42-AA-5B-69-7E-B6-D4-A6-13
[Certificate] Version:           3
[Certificate] Issuer name:       thedomain.local
[Certificate] Subject name:      thedomain.local
[Certificate] Not Before:        7/11/2022 6:28:05 AM +00:00
[Certificate] Not After:         7/11/2023 6:28:05 AM +00:00
[Certificate] Validity period:   365.00:00:00
[Certificate] SignatureAlgo OID: 1.3.14.3.2.29
[Certificate] PublicKeyInfo OID: 1.2.840.113549.1.1.1
[Certificate] RSA Key Size:      2048 bits
[Certificate] Certificate Guid:  d799cd2d-8ac2-4242-aa5b-697eb6d4a613

[+] Validating certificate format

[+] Setting up connection with Domain Controller: dc.thedomain.local
[+] New Backup Key to be created     : G$BCKUPKEY_d799cd2d-8ac2-4242-aa5b-697eb6d4a613
[+] New Backup Key created successfully     : G$BCKUPKEY_d799cd2d-8ac2-4242-aa5b-697eb6d4a613
[+] Setting BackupKey value...
[+] BackupKey value was set successfully!
[+] Modified preferred backup GUID to: d799cd2d-8ac2-4242-aa5b-697eb6d4a613
```



## bkrp_test

The BackupKeyManager tool provides information on what and how you can use it.
There are few verbs alongside with specific flags you can set according to your needs.

### Usage:

```
C:\BackupKeyManager\bkrp_test>bkrp_test_x64.exe
Usage: bkrp_test_x64.exe <DC>

```

### Get the domain served Backupkey GUID:

```
C:\BackupKeyManager\bkrp_test>bkrp_test_x64.exe dc.thedomain.local
[+] Retrieving the current BackupKey public certificate
   > Certificate size: 768
   > Guid: d799cd2d-8ac2-4242-aa5b-697eb6d4a613
    > Attempting secret encrypt (MySecret!).... OK
    > Attempting secret decrypt.... OK -> MySecret!

```



## Build

TBD