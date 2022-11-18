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

This repository contains two projects:
* BackupKeyManager - The main Backup Key modification tool (C#) + MS-BKRP dpendency DLL (C)
* user-key-onboarding - A utility to onboard existing AD users to the domain backup key (PS)

### Create and onboard new DPAPI Backup key flow:

1. First, you will have to use the BackupKeyManager to extract the currently used (preferred) BackupKey. Write Down its GUID in case you will need to revert back to it.
2. Use the BackupKeyManager to create and prefer a new backup key in the domain (Note to write down the generated GUID).
3. A restart will be required to the DC as we must reload the LSASS process.
4. Use the BackupKeyManager to validate that the certificate's GUID being served is identical to the one generated during step #1.
5. From a domain user context, execute the user-key-onboarding with either the soft or forced method. Note which user Master keys are using the new backup key (Compare GUID).
6. Repeat step #4 for every user you would like to onboard to the new key.



## BackupKeyManager

The BackupKeyManager help provides information on what and how you can use it.
There are few verbs alongside with specific flags you can set according to your needs.
It is important to use this tool together with the Primary domain controller (PDC).

### Verbs required privileges
Domain Admin privileges required for:
- GetPreferredBackupKey
- GetBackupKeyByGUID
- SetPreferredBackupKeyByGUID
- GenerateNewBackupKey (Only when using the push flag)
- BackupKeyFromFile (Only when using the push flag)
- Validate

Any Domain User privileges required for:
- Fetch



### List verbs:

```
C:\BackupKeyManager>BackupKeyManager.exe --help
BackupKeyManager 1.0.0.0
Copyright c  2022

  GetPreferredBackupKey          Extract the preferred (current) backup key

  GetBackupKeyByGUID             Extract a BackupKey value by GUID

  SetPreferredBackupKeyByGUID    Set a new preferred bakupkey by providing its GUID

  GenerateNewBackupKey           Generate GUID and new backup key with option to push and set as preferred.

  BackupKeyFromFile              Load Backup key from file with option to push it and set it as preferred.

  Validate                       Validates that the Backup Key was setup correctly and will be served to clients
                                 according to the Preferred Backup key. This check should be made against all DCs in the
                                 domain.

  Fetch                          Fetch the public Backup key certificate via MS-BKRP (Non-Admin operation).

  help                           Display more information on a specific command.

  version                        Display version information.


[+] Operation completed
```

### List specific verb's flags:

```
C:\BackupKeyManager>BackupKeyManager.exe GenerateNewBackupKey --help
BackupKeyManager 1.0.0.0
Copyright c  2022

  -d, --DomainName          Required. (Required) FQDN of the required domain. This will be included in the public
                            certificate.

  -o, --OutputFile          (Optional) Dump Backupkey and certificate DER format outputs to files

  --push                    (Optional) Push the generated backup key to a Domain Controller.

  -s, --DomainController    (Depend on 'push' usage) Primary Domain Controller DNS Address to interact with.

  --set                     (Depend on 'push' usage) Set the generated Backup key as the Preferred Backup key.

  --help                    Display this help screen.

  --version                 Display version information.


[+] Operation completed
```


### Get information about the currently active (preferred) BackupKey via MS-LSAD protocol (Domain Admin is required):

```
C:\BackupKeyManager>BackupKeyManager.exe GetPreferredBackupKey -s dc.domain.local --analyze

[+] Setting up connection with Domain Controller: dc.windomain.local
[+] Preferred backupkey Guid         : 170e6701-8213-48ce-bf52-1be5b6f1ab1e
[+] Getting backup key     : G$BCKUPKEY_170e6701-8213-48ce-bf52-1be5b6f1ab1e
[+] BackupKey size: 1952

[+] Validating BackupKey header...

[+] Analyzing certificate information:
[Certificate] Serial Number:     1E-AB-F1-B6-E5-1B-52-BF-48-CE-82-13-17-0E-67-01
[Certificate] Version:           3
[Certificate] Issuer name:       domain.local
[Certificate] Subject name:      domain.local
[Certificate] Not Before:        7/21/2022 1:33:28 PM +00:00
[Certificate] Not After:         7/21/2023 1:33:28 PM +00:00
[Certificate] Validity period:   365.00:00:00
[Certificate] SignatureAlgo OID: 1.3.14.3.2.29
[Certificate] PublicKeyInfo OID: 1.2.840.113549.1.1.1
[Certificate] RSA Key Size:      2048 bits
[Certificate] Certificate Guid:  170e6701-8213-48ce-bf52-1be5b6f1ab1e

[+] Validating Certificate format...

[+] Operation completed

```

### Generate new BackupKey and use it as the preferred BackupKey :

```
C:\BackupKeyManager>BackupKeyManager.exe GenerateNewBackupKey -d domain.local -s dc.domain.local --set --push

[+] Generated Guid: 1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e

[+] Generating 2048 bit RSA Key pair...
[+] Creating certificate
[+] Building the new Domain BackupKey...
[+] BackupKey size: 1952

[+] Analyzing certificate information:
[Certificate] Serial Number:     7E-1B-5F-EF-0A-AD-A0-EC-06-42-3D-6C-1E-2B-65-67
[Certificate] Version:           3
[Certificate] Issuer name:       domain.local
[Certificate] Subject name:      domain.local
[Certificate] Not Before:        11/18/2022 5:39:16 AM +00:00
[Certificate] Not After:         11/18/2023 5:39:16 AM +00:00
[Certificate] Validity period:   365.00:00:00
[Certificate] SignatureAlgo OID: 1.3.14.3.2.29
[Certificate] PublicKeyInfo OID: 1.2.840.113549.1.1.1
[Certificate] RSA Key Size:      2048 bits
[Certificate] Certificate Guid:  1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e

[+] Validating BackupKey header...

[+] Validating Certificate format...

[+] Setting up connection with Domain Controller: dc.domain.local
[+] Creating Backup key with name     : G$BCKUPKEY_1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e
[+] New Backup key created successfully     : G$BCKUPKEY_1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e
[+] Writing bytes to Backup key...
[+] Backup key uploaded successfully
[+] Modified preferred backup GUID to: 1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e

[?] You must restart the targeted Domain Controller for the changes to take effect

[+] Operation completed
```

### ** Restart The targeted Domain Controller **


### To make sure we did not break anything we must use Validate :
Make sure the output does not contain any error message

```
C:\BackupKeyManager>BackupKeyManager.exe Validate -s dc.domain.local

[+] Setting up connection with Domain Controller: dc.domain.local
[+] Preferred Backupkey Guid         : 1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e

[+] Retrieving the current BackupKey public certificate via MS-BKRP...OK -> Certificate size: 768
[+] MS-BKRP Serviced Backupkey Guid         : 1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e

[+] SUCCESS! The serviced Backup Key (MS-BKRP) and the Preferred Backup key (MS-LSAD) are synced

[+] Validating MS-BKRP protocol health
    > Attempting secret encrypt (MySecret!).... OK
    > Attempting secret decrypt.... OK -> MySecret!

[+] SUCCESS! MS-BKRP secret encryption & decryption passed!

[+] Operation completed

```


### Fetch the currently served public backup key (Non-Admin) :
You may want to check what is served by the Domain Controller via the MS-BKRP protocol, and retreive informaton about the certificate

```
C:\BackupKeyManager>BackupKeyManager.exe Fetch -s dc.domain.local --analyze

[+] Retrieving the current BackupKey public certificate via MS-BKRP...OK -> Certificate size: 768
[+] MS-BKRP Serviced Backupkey Guid         : 1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e

[+] Analyzing certificate information:
[Certificate] Serial Number:     7E-1B-5F-EF-0A-AD-A0-EC-06-42-3D-6C-1E-2B-65-67
[Certificate] Version:           3
[Certificate] Issuer name:       domain.local
[Certificate] Subject name:      domain.local
[Certificate] Not Before:        11/18/2022 5:39:16 AM +00:00
[Certificate] Not After:         11/18/2023 5:39:16 AM +00:00
[Certificate] Validity period:   365.00:00:00
[Certificate] SignatureAlgo OID: 1.3.14.3.2.29
[Certificate] PublicKeyInfo OID: 1.2.840.113549.1.1.1
[Certificate] RSA Key Size:      2048 bits
[Certificate] Certificate Guid:  1e2b6567-3d6c-0642-eca0-ad0aef5f1b7e

[+] Validating Certificate format...

[+] Operation completed

```


## Build

TBD