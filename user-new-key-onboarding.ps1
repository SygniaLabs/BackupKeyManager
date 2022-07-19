function Get-ADUserMasterKeyLocation {
    $userSID = (New-Object System.Security.Principal.NTAccount($env:username)).Translate([System.Security.Principal.SecurityIdentifier]).value
    $mkPath = $env:APPDATA + "\Microsoft\Protect\" + $userSID
    return $mkPath;
}


function Get-CurrentFileTimeBytes {
    $ticksNow = (get-date).ToFileTimeUtc();
    [byte[]] $ftNowByte = [System.BitConverter]::GetBytes($ticksNow);
    return $ftNowByte   
}



function Describe-PreferredFile {
    param(
    [Parameter (Mandatory = $true)] [Byte[]]$preferredBytes
    )

    # Debug
    #Format-Hex -InputObject $preferredBytes

    ## Describe Guid
    [byte[]] $guidBytes = $preferredBytes[0..15]
    [Guid] $mkGuid = [Guid]($guidBytes);
    Write-Output ("[-] Preferred Master key Guid: " + $mkGuid.Guid);
    

    ## Describe current expiration date    
    [byte[]] $ftMK = $preferredBytes[16..23];
    [int64] $ftMKTicks = [System.BitConverter]::ToInt64($ftMK,0);
    $currExp = [datetime]::FromFileTimeUTC($ftMKTicks);
    Write-Output ("[-] Preferred Master key Expiration: " + $currExp + " UTC");


    ## Decribe preferred MK backup key guid
    [byte[]] $prefMasterKey = Get-PreferredMasterKeyFile($mkLocation);
    [Guid] $mkBkpGuid = Get-MasterKeyBkpGuid($prefMasterKey);
    Write-Output ("[-] Preferred Master key Backup key Guid: " + $mkBkpGuid);

}


function Get-MasterKeyBkpGuid {
    param(
    [Parameter (Mandatory = $true)] [Byte[]]$masterKeyBytes
    )

    [int] $mkHeaderLengthsOffset = 12+72+12
    [int] $mkHeaderLen = $mkHeaderLengthsOffset + (8*4);
   
   
    [byte[]] $mkSec1LenByte = $prefMasterKey[$mkHeaderLengthsOffset..($mkHeaderLengthsOffset+7)]
    [uint64] $mkSec1Len = [System.BitConverter]::ToUint64($mkSec1LenByte, 0);
   
   
    [byte[]] $mkSec2LenByte = $prefMasterKey[($mkHeaderLengthsOffset+8)..($mkHeaderLengthsOffset+7+8)]
    [uint64] $mkSec2Len = [System.BitConverter]::ToUint64($mkSec2LenByte, 0);
   
    [byte[]] $mkSec3LenByte = $prefMasterKey[($mkHeaderLengthsOffset+16)..($mkHeaderLengthsOffset+7+16)]
    [uint64] $mkSec3Len = [System.BitConverter]::ToUint64($mkSec3LenByte, 0);
   
    [byte[]] $mkSec4LenByte = $prefMasterKey[($mkHeaderLengthsOffset+24)..($mkHeaderLengthsOffset+7+24)]
    [uint64] $mkSec4Len = [System.BitConverter]::ToUint64($mkSec4LenByte, 0);
   
   
    [int] $domBkpKeyOffset = $mkHeaderLen + $mkSec1Len + $mkSec2Len + $mkSec3Len
    [byte[]] $domBkpKeyBytes = $prefMasterKey[$domBkpKeyOffset..($domBkpKeyOffset+$mkSec4Len)]
    [byte[]] $domBkpKeyGuidBytes = $domBkpKeyBytes[12..27]
    [Guid] $bkpGuid = [Guid]($domBkpKeyGuidBytes);

    return $bkpGuid
}


function Get-PreferredFile {
    param(
    [Parameter (Mandatory = $true)] [String]$preferredPath
    )
    $preferredPath += "\Preferred";
    #Write-OUtput $preferredPath
    [byte[]]$preferredFile = Get-Content $preferredPath -Encoding byte
    return ,$preferredFile
}


function Get-MasterKeyFile {
    param(
    [Parameter (Mandatory = $true)] $mkLocation,
    [Parameter (Mandatory = $true)] [String]$mkName
    )
    $mkPath = $mkLocation + "\" + $mkName;
    [byte[]]$mkFile = Get-Content $mkPath -Encoding byte
    return ,$mkFile
}


function Get-PreferredMasterKeyFile {
    param(
    [Parameter (Mandatory = $true)] [String]$mkLocation
    )
    [byte[]] $prefBytes = Get-PreferredFile($mkLocation);
    [byte[]] $guidBytes = $prefBytes[0..15]
    [Guid] $prefGuid = [Guid]($guidBytes);
    [String] $prefGuidStr = $prefGuid.ToString();
    [byte[]] $prefMK = (Get-MasterKeyFile $mkLocation $prefGuidStr);
    return ,$prefMK
}



function Expire-MasterKey {
    param(
    [Parameter (Mandatory = $true)] [Byte[]]$GuidBytes,
    [Parameter (Mandatory = $true)] [String]$preferredPath
    )
    Write-Output ("[+] Setting expiration to: " + [datetime]::UtcNow);
    $preferredPath += "\Preferred";
    [byte[]] $newExpiration = Get-CurrentFileTimeBytes
    [byte[]] $newPreferred = $GuidBytes + $newExpiration;
    Write-Output ("[+] Saving Data to: " + $preferredPath);
    Set-Content -Path $preferredPath -Value $newPreferred -Encoding Byte;
}


function Rename-BKPublic {
    param(
    [Parameter (Mandatory = $true)] [String]$mkPath
    )
    $nbDomainName = $env:userdomain;
    $bkName = "BK-" + $nbDomainName;
    $bkPath = ($mkPath + "\" + $bkName);
    Write-Output ("[-] Checking public backup key existence..");
    if (Test-Path -Path $bkPath -PathType leaf)
       {
        $newbkName = $bkName + "_" + (get-date).ticks;
        Write-Output ("[+] Renaming old public key: " + $bkName + " to " + $newbkName );
        Rename-Item -Path $bkPath -NewName ($newbkName);
       }
    else {
       Write-Output ("[!] Public backup key does not exist or not in the correct path: " + $bkPath);
       }
}



function Trigger-DPAPIProtect {
    [byte[]] $dummyData = @(0x44, 0x55, 0x4D, 0x4D, 0x59);
    [byte[]] $dummyEntropy = @(0x1);
    $scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser;
    [System.Security.Cryptography.ProtectedData]::Protect($dummyData, $dummyEntropy, $scope);
}




function Invoke-BkpOnboard {
    param(
    [Parameter (Mandatory = $true)] [String]$Mode
    )

    if (($env:USERDNSDOMAIN).length -le 2){
        Write-Output ("[!] ERROR: Not in a domain context");
        exit;
    }


    Add-Type -AssemblyName System.Security

    # Vars
    [String] $mkLocation = (Get-ADUserMasterKeyLocation);
    
    
    # Reading Preferred file
    if (($Mode -eq "Info") -or ($Mode -eq "Soft") -or ($Mode -eq "Forced"))
    {  
        
        Write-Output ("");      
        [byte[]] $prefBytes = Get-PreferredFile($mkLocation);
        Describe-PreferredFile($prefBytes);




        
        if (($Mode -eq "Soft") -or ($Mode -eq "Forced"))
        {          
                       
            # AD connection test
            Write-Output ("");
            Write-Output ("[-] Checking connection to the Active Directory: " + $env:USERDNSDOMAIN);
            $adconnection = Test-Connection -ComputerName $env:USERDNSDOMAIN -Protocol DCOM -Count 2 -Quiet;
            if (-Not $adconnection){
                Write-Output ("[!] Cannot reach the Active Directory, exiting!");
                exit;
            }

        
        
        
            [byte[]] $prefMasterKey = Get-PreferredMasterKeyFile($mkLocation);
            [Guid] $oldMkBkpGuid = Get-MasterKeyBkpGuid($prefMasterKey);





            

            # Expire current Master key
            Write-Output ("");
            Expire-MasterKey $prefBytes[0..15] $mkLocation;
            


            # Rename the older public Bakcup key
            Write-Output ("");
            Rename-BKPublic($mkLocation);


            Start-Sleep -Seconds 2 # Wait for files operations


            # Trigger DPAPI
            Write-Output ("");
            Write-Output ("[-] Triggering DPAPI Master key generation...");
            $dpapi = Trigger-DPAPIProtect;


            Start-Sleep -Seconds 2 # Wait for DPAPI operation.
            

            # List new Master keys
            #Get-ChildItem -Path $mkLocation -Hidden | sort LastWriteTime -Descending;


            Write-Output ("");
            [byte[]] $newPrefBytes = Get-PreferredFile($mkLocation);
            Describe-PreferredFile($newPrefBytes);



            [byte[]] $newPrefMKBytes = Get-PreferredMasterKeyFile($mkLocation);
            [Guid] $newPrefBkpGuid = Get-MasterKeyBkpGuid($newPrefMKBytes);

            
            Write-Output ("");
            Write-Output ("[-] Validating new backup key usage...");
            if($oldMkBkpGuid -ne $newPrefBkpGuid)
            {
              
              Write-Output ("[+] Successfully onboarded " + $env:USERNAME + " to use new backup key with Guid: " + $newPrefBkpGuid);
            }
            else {
                
              Write-Output ("[?] User already onboarded to Backup key with Guid: "+ $newPrefBkpGuid);
            }


        }
    }
}
