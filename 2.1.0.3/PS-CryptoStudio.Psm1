Function New-RootSubCA
	{
	<#
	.SYNOPSIS
             Creates a two tier CA.
             Version 2.1.0.2

    .DESCRIPTION
             Creates a root certificate and two subordinate certificates (SubCa)

    .PARAMETER RootKeyLength 
            Specifies the length of the Root CA key-values are 1, 2, 4, 8, 16 

    .PARAMETER SubCA01KeyLength
            Specifies the length of the the first Sub CA key-values are 1, 2, 4, 8, 16
    
    .PARAMETER SubCA02KeyLength
            Specifies the length of the the second Sub CA key-values are 1, 2, 4, 8, 16

    .EXAMPLE
		    PS> New-RootSubCa -RootKeyLength 4 -SubCA01KeyLength 4 -SubCA02KeyLength 4

    .INPUTS
		    None.

    .NOTES
		    Requirements: Windows 10 17.09 or better or Server 2016 or better
      Requirements: Windows PowerShell 5.1

      Max Encrypt size RSA ((KeySize - 384) / 8) + 37
                            
    #>  
    [CmdletBinding()]
    Param(
       [Parameter(Mandatory=$True)]       
       [ValidateSet("1", "2", "4", "8", "16")]
       [Int]$RootKeyLength,

       [Parameter(Mandatory=$True)]  
       [ValidateSet("1", "2", "4", "8", "16")]
       [Int]$SubCA01KeyLength,

       [Parameter(Mandatory=$True)]  
       [ValidateSet("1", "2", "4", "8", "16")]
       [Int]$SubCA02KeyLength,

       [Parameter(Mandatory=$False)]
       [Int]$Days
       )

# Declare functions
# Get passwords for certificates function 
  Function Get-Password ($CertName)
    {
       $ChkSecure=0
     Do
       {
        $SecurePassword  = Read-Host -Prompt "Enter password for $CertName" -AsSecureString
        $SecurePassword2 = Read-Host -Prompt "Please verify password for $CertName" -AsSecureString
        If ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)) -eq [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword2)))
           {
            $ChkSecure=1
           }

       Else
          {
           $ChkSecure=0
           Write-Host "Passwords do not match" -ForegroundColor Red
          }
            
       } While ($ChkSecure -eq 0)
       Return $SecurePassword

    }
# End function declaration
 
# Check to see if PS-CryptoStudio is already installed
  If (Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object {$_.Issuer -match "PS-CryptoStudio"} )
    {
     Write-Host "Error-PowerShell CryptoStudio RootSubCa already installed." -ForegroundColor Red
     Break
    }

# Check if run as administrator
  If (! ((New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )))
      {
       Write-Host "Not running as administrator`nRerun with administrative privilages" -ForegroundColor Red
       Break
      }

# Check OS version
  $OSInfo = Get-WmiObject -class Win32_OperatingSystem
  If ([INT]$OSVersion=($OSInfo.Version).Substring(0,2) -lt 10)
      {
       Write-Host "Invalid Operating System`nWindows 10 or Server 2016 or greater" -ForegroundColor Red
       Break
      }

# Configure number of days for validity
  If ($Days -lt 1)
    {
     $Days=365
    }

# Confirm before continuing 
  $Read=Read-Host "This will install a Root-SubCa(x2)-`'c`' to continue-Anything else aborts"
  If ($Read -ne "c" -or $Read -ne "C")
      {
	   Write-Host "Exiting" -ForegroundColor Cyan
	   Break
      }

# Get domain name, if any  
  $DNSRoot=$Null
  If ($env:USERDNSDOMAIN)
    {
     $DNSRoot="." + $env:USERDNSDOMAIN
    }
  
# Define variables-force revalidation.
  [ValidateRange(0, 16384)]$RootKeyLength    = $RootKeyLength    * 1024
  [ValidateRange(0, 16384)]$SubCA01KeyLength = $SubCA01KeyLength * 1024
  [ValidateRange(0, 16384)]$SubCA02KeyLength = $SubCA02KeyLength * 1024

  Clear-Host

# Get passwords for certs
  $RootCertPWD = Get-Password  "Root Cert"
  $SubCa01PWD  = Get-Password  "SubCa-01"
  $SubCa02PWD  = Get-Password  "SubCa-02"
 
# CertStore Variables
  $SourceStoreScope = 'LocalMachine';$SourceStorename = 'My';$DestStoreScope = 'LocalMachine';$DestStoreName = 'root'
  $CertStore="$Env:UserProfile\Documents\MyCerts";$CertStorePublic=$CertStore + "\Public";$CertStorePrivate=$CertStore + "\Private"
  $CertStoreCSR=$CertStore + "\CSR"
  $AESPath = "$CertStore\AES"; $AESKeyPath="$CertStore\AES\Type-001.TeeStar";$CertEncStore=$CertStore + "\Enc"

# Root Variables
  $RootFriendlyName="PS-Crypto_RooT-01";$Subject="PS-CryptoStudio_RooTCA";$RootCert="PS-Crypto_RootCert.Cer";$RootPrivateName="PS-Crypto_RootCert.Pfx"
  $FullDNSName=$env:COMPUTERNAME + $DNSRoot;$CertTumbPrint=$null
  [DateTime]$RootVaild= ((Get-Date).AddDays($Days))

# SubCA01 Variables
  $SubFriendlyName01="PS-Crypto_SubCa-01";$SubCertName01="PS-Crypto_SubCert01.Cer";$SubCertPrivateName01="PS-Crypto_SubCert01.Pfx"
  $SubCaSubject01="PS-Crypto_SubCa-01"
  [DateTime]$SubCA01Vaild= ((Get-Date).AddDays($Days))

# SubCA02 Variables
  $SubFriendlyName02="PS-Crypto_SubCa-02";$SubCertName02="PS-Crypto_SubCert02.Cer";$SubCertPrivateName02="PS-Crypto_SubCert02.Pfx"
  $SubCaSubject02="PS-Crypto_SubCa-02"
  [DateTime]$SubCA02Vaild= ((Get-Date).AddDays($Days))
  
# Create CertStore Directories
  New-Item $CertStorePublic  -ItemType Directory -Force |Out-Null
  New-Item $CertStorePrivate -ItemType Directory -Force |Out-Null
  New-Item $AESPath          -ItemType Directory -Force |Out-Null
  New-Item $CertStoreCSR     -ItemType Directory -Force |Out-Null

  Clear-Host
#
# Create New Root Certificate
#
  Write-Host "Generating Root Certificate-Keylength $RootKeyLength Friendly Name-$RootFriendlyName. Valid untill $RootVaild" -ForegroundColor Cyan
  $Elapsed = [System.Diagnostics.Stopwatch]::StartNew() 
  $Root= New-SelfSignedCertificate -KeyUsage KeyEncipherment, DataEncipherment, CertSign  -NotAfter $RootVaild  -HashAlgorithm SHA256 -KeyUsageProperty All -TextExtension @("2.5.29.19 ={critical} {text}ca=1&pathlength=3") -KeyLength $RootKeyLength  -FriendlyName $RootFriendlyName -Subject $Subject -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -certstorelocation cert:\localmachine\My -dnsname $FullDNSName
  $CertTumbPrint=$Root.Thumbprint
  Write-Host "Created Root certificate in-: $($Elapsed.Elapsed.ToString())" -ForegroundColor Green
#
# Place public certificate in Root
  Export-Certificate -Cert $Root -FilePath $CertStorePublic\$RootCert -Type CERT  -Force | Out-Null
  $Root|Export-PfxCertificate -FilePath "$CertStorePrivate\$RootPrivateName" -Password $RootCertPWD | Out-Null
  
  Import-Certificate -FilePath $CertStorePublic\$RootCert -CertStoreLocation cert:\LocalMachine\Root |Out-Null
  Get-ChildItem Cert:\LocalMachine\CA | Where-Object {$_.Thumbprint -eq $CertTumbPrint} | Remove-Item -Force
  Write-Host "Root certificate with thumbprint->$CertTumbPrint installed in Root`n" -ForegroundColor Green
#
# Create New Subordinate Certificate-001
#
  Write-Host  "Creating Subordinate Certificate01-Keylength $SubCA01KeyLength Friendly Name-$SubFriendlyName01. Valid untill $SubCA01Vaild" -ForegroundColor Cyan
  $Elapsed  = [System.Diagnostics.Stopwatch]::StartNew()
  $SubCert01= New-SelfSignedCertificate -KeyUsage KeyEncipherment, DataEncipherment, CertSign -NotAfter $SubCA01Vaild -KeyUsageProperty All -HashAlgorithm SHA256  -TextExtension @("2.5.29.19 = {critical} {text}ca=1&pathlength=0") -Subject $SubCaSubject01 -KeyLength $SubCA01KeyLength -Signer $Root -FriendlyName $SubFriendlyName01 -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"  -certstorelocation cert:\localmachine\my -dnsname $FullDNSName9
  $SubCA01Thumbprint=$SubCert01.Thumbprint
  Get-ChildItem Cert:\LocalMachine\CA | Where-Object {$_.Thumbprint -eq $SubCA01Thumbprint} | Remove-Item -Force
  Write-Host "Created SubCert01 in-: $($Elapsed.Elapsed.ToString())" -ForegroundColor Green
#
# Place public certificate in CA Store (Intermediate Certification Authorities)
  Export-Certificate -Cert $SubCert01 -FilePath $CertStorePublic\$SubCertName01 -Type CERT  -Force | Out-Null
  $SubCert01|Export-PfxCertificate -FilePath "$CertStorePrivate\$SubCertPrivateName01" -Password $SubCa01PWD | Out-Null
  Import-Certificate -FilePath "$CertStorePublic\$SubCertName01" -CertStoreLocation Cert:\LocalMachine\CA |Out-Null
  Write-Host "SubCA01 certificate with thumbprint->$SubCA01Thumbprint installed in CA Store (Intermediate Certification Authorities) `n" -ForegroundColor Green
#
# Create New Subordinate Certificate-002
# 
  Write-Host  "Creating Subordinate Certificate02-Keylength $SubCA02KeyLength Friendly Name-$SubFriendlyName02. Valid untill $SubCA02Vaild" -ForegroundColor Cyan
  $Elapsed  = [System.Diagnostics.Stopwatch]::StartNew()
  $SubCert02= New-SelfSignedCertificate -KeyUsage KeyEncipherment, DataEncipherment, CertSign  -NotAfter $SubCA02Vaild -KeyUsageProperty All -HashAlgorithm SHA256  -TextExtension @("2.5.29.19 = {critical} {text}ca=1&pathlength=0") -Subject $SubCaSubject02 -KeyLength $SubCA02KeyLength -Signer $Root -FriendlyName $SubFriendlyName02 -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"  -certstorelocation cert:\localmachine\my -dnsname $FullDNSName
  $SubCA02Thumbprint=$SubCert02.Thumbprint
  Get-ChildItem Cert:\LocalMachine\CA | Where-Object {$_.Thumbprint -eq $SubCA02Thumbprint} | Remove-Item -Force
  Write-Host "Created SubCert02 in-: $($Elapsed.Elapsed.ToString())" -ForegroundColor Green
#
# Place public certificate in CA Store (Intermediate Certification Authorities)
  Export-Certificate -Cert $SubCert02 -FilePath $CertStorePublic\$SubCertName02 -Type CERT  -Force | Out-Null
  $SubCert02|Export-PfxCertificate -FilePath "$CertStorePrivate\$SubCertPrivateName02" -Password $SubCa02PWD | Out-Null
  Import-Certificate -FilePath "$CertStorePublic\$SubCertName02" -CertStoreLocation Cert:\LocalMachine\CA |Out-Null
  Write-Host "SubCA02 certificate with thumbprint->$SubCA02Thumbprint installed in CA Store (Intermediate Certification Authorities) `n" -ForegroundColor Green

# List all created certificates  
  Write-Host "`n`nCerts created" -ForegroundColor Magenta
  $Root, $SubCert01, $SubCert02 | Select-Object Subject, Issuer, Thumbprint | Sort-Object -Property Subject

	}

Function New-HostCert
    {
   <#
	.SYNOPSIS
             Creates certificates for a host using existing PowerShell CryptoStudio RootCA and SubCAs
             Version 2.1.0.2

    .DESCRIPTION
             Creates two certificates for a host (using SubCA01 and SubCa02). Stores both public and private keys in Documents\MyCerts folder

    .PARAMETER HostName 
            Specifies the subject name for the host. This is also included in the Subject Alternate Names (SAN) list.

    .PARAMETER SANName
            Specifies the FQDN of the host. Multiple hosts can be declared seperated by commas 
    
    .PARAMETER FriendlyName
            Specifies the 'friendly name' of the certificate

    .PARAMETER HostKeyLength
            Specifies the length of the Host key- valid values are 1, 2, 4, 8, 16 (to be multiplied by 1K or 1024)

    .PARAMETER InstallCertLocal
            Switch to determine if certificates should be installed in local cert store.

    .EXAMPLE
		    PS> New-HostCert -HostName "myhost.com" -SANName "vpn.myhost.com", "mail.myhost.com", "remote.myhost.com" -FriendlyName "My Test Cert" -HostkeyLength 4

    .INPUTS
		    None.

    .NOTES
		    Requirements: Windows 10 17.09 or better or Server 2016 or better
      Requirements: Windows PowerShell 5.1

      Max Encrypt size RSA ((KeySize - 384) / 8) + 37
      However, if the optimal asymmetric encryption padding (OAEP) parameter is true, the following can be used to calculate the max bytes: ((KeySize - 384) / 8) + 7

     #> 
          
     [CmdletBinding()]
param(
	[Parameter( Mandatory=$true)]
	[string]$HostName,

	[Parameter( Mandatory=$false)]
	[Array]$SANName,

    [Parameter( Mandatory=$true)]
	[string]$FriendlyName,
    
    [Parameter(Mandatory=$True)]       
    [ValidateSet("1", "2", "4", "8", "16")]
    [Int]$HostKeyLength,

    [Parameter(Mandatory=$False)]
    [Switch]$InstallCertLocal,

    [Parameter(Mandatory=$False)]
    [Int]$Days
	)

	
# Check if run as administrator
  If (! ((New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )))
      {
       Write-Host "Not running as administrator`nRerun with administrative privilages" -ForegroundColor Red
       Break
      }

# Check OS version
  $OSInfo = Get-WmiObject -class Win32_OperatingSystem
  If ([INT]$OSVersion=($OSInfo.Version).Substring(0,2) -lt 10)
      {
       Write-Host "Invalid Operating System`nWindows 10 or Server 2016 or greater" -ForegroundColor Red
       Break
      }
  
#CertStore Variables
  $SourceStoreScope = 'LocalMachine';$SourceStorename = 'My';$DestStoreScope = 'LocalMachine';$DestStoreName = 'root'
  $CertStore="$Env:UserProfile\Documents\MyCerts";$CertStorePublic=$CertStore + "\Public";$CertStorePrivate=$CertStore + "\Private"
  $CertStoreCSR=$CertStore + "\CSR"
  $AESPath = "$CertStore\AES"; $AESKeyPath="$CertStore\AES\Type-001.TeeStar";$CertEncStore=$CertStore + "\Enc"

#Cert Variables
  $CertIssuerMatch="CryptoStudio_RooTCA";$CertSub="PS-Crypto_SubCa";$Count=1
  $FriendlyName += "-CryptoStudio"

  New-Item $CertStorePublic  -ItemType Directory -Force |Out-Null
  New-Item $CertStorePrivate -ItemType Directory -Force |Out-Null
  New-Item $AESPath          -ItemType Directory -Force |Out-Null
  New-Item $CertEncStore     -ItemType Directory -Force |Out-Null

  [ValidateRange(0, 16384)]$HostKeyLength = $HostKeyLength * 1024
  $SANName                               += $HostName
  If ($Days -lt 1)
    {
     $Days=365
    }
  [DateTime]$CertValid                    = ((Get-Date).AddDays($Days))
# Get signing certificates
  $SubCerts= Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match $CertIssuerMatch} | Where-Object {$_.Subject -match $CertSub}
  If (! $SubCerts)
      {
       Write-Host "`nCertificate signed by SubCa for $CertSub does not exist!" -ForegroundColor Red
       Break
      }
# Check to make sure certifcates can sign  
  ForEach ($SubCert in $SubCerts)
      {
       If ($SubCert.Extensions.oid.Value -notcontains "2.5.29.19")
            {
             Write-Host "`nCertificate" ($SubCert.Thumbprint) "is invalid" -ForegroundColor Red
             Break
            }
      }
  Clear-Host
# Get Password for Certs
  Do
      {
       $SecurePassword  = Read-Host -Prompt "Enter password for certificates" -AsSecureString
       $SecurePassword2 = Read-Host -Prompt "Please verify password for certificates" -AsSecureString
       If ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)) -eq [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword2)))
          {
           $ChkSecure=1
          }

       Else
          {
           $ChkSecure=0
           Write-Host "Passwords do not match" -ForegroundColor Red
          }
            
      } While ($ChkSecure -eq 0)

# Create computer certificates  
  $Count=1;$Certs=@()
  Try
      {
       ForEach ($SubCert in $SubCerts)
          {
           $FriendlyCert=$FriendlyName + "-SubCA-0" + $Count
           Write-Host "Generating Computer Certificate01-Keylength $HostKeyLength Friendly Name-$FriendlyCert" -ForegroundColor Cyan
           $Elapsed = [System.Diagnostics.Stopwatch]::StartNew() 
           $CompCert= New-SelfSignedCertificate -KeyUsage KeyEncipherment, DataEncipherment -KeyUsageProperty All -NotAfter $CertValid -HashAlgorithm SHA256  -Subject $HostName -KeyLength $HostKeyLength -Signer $SubCert -FriendlyName $FriendlyCert -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -certstorelocation cert:\localmachine\my -dnsname $SANName 
          # Export Public Key   
           Export-Certificate -Cert $CompCert -FilePath  "$CertStorePublic\$HostName-SubCa0$Count.Cer" -Type CERT  -Force | Out-Null
          # Export Private Key
           $CompCert| Export-PfxCertificate -FilePath "$CertStorePrivate\$HostName-SubCa0$Count.Pfx" -Password $SecurePassword | Out-Null
           $Certs +=$CompCert
           Write-Host "Created computer certificate in-:$($elapsed.Elapsed.ToString())"  -ForegroundColor Green
           $Count ++  
          If ($InstallCertLocal)
            {
             Write-Host "Created computer certificate for $HostName and placed the certificate with the thumbprint->" $CompCert.ThumbPrint " in the Personal store`n`n" -ForegroundColor Green
            }
          Else 
            {
             ForEach ($Cert in $Certs)
                {
                # Delete cert  
                 Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -contains ($Cert.Thumbprint)} |Remove-Item -Force
                }
            }
        }

       Write-Host "`n`nCerts created" -ForegroundColor Magenta
       $Certs | Select-Object Subject, Issuer, Thumbprint | Sort-Object -Property Subject
      }

  Catch
      {
       Write-Output "`n`nError creating certificate-Check parameters and try again"
       Break
      }



    }

Function Remove-RootSubCA
    {
     <#
	.SYNOPSIS
             Removes RootCA and SubCAs created by New-RootSubCA
             Version 1.0.0.4

    .DESCRIPTION
             Removes RootCA and SubCAs created by New-RootSubCA. Also deletes RootCA and SubCAs from MyCerts directory. Does not delete other certificates signed by SubCAs

    .EXAMPLE
		     PS> Remove-RootSubCA

    .INPUTS
		     None.

    .OUTPUTS
             None.

    .NOTES
		     Requirements: Windows 10 17.09 or better or Server 2016 or better
       Requirements: Windows PowerShell 5.16                
    #>  
    
    # Check if run as administrator
     If (! ((New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )))
        {
         Write-Host "Not running as administrator`nRerun with administrative privilages" -ForegroundColor Red
         Break
        }

    # Check OS version
       $OSInfo = Get-WmiObject -class Win32_OperatingSystem
     If ([INT]$OSVersion=($OSInfo.Version).Substring(0,2) -lt 10)
        {
         Write-Host "Invalid Operating System`nWindows 10 or Server 2016 or greater" -ForegroundColor Red
         Break
      }
     
    # CertStore Variables
       $SourceStoreScope = 'LocalMachine';$SourceStorename = 'My';$DestStoreScope = 'LocalMachine';$DestStoreName = 'root'
       $CertStore="$Env:UserProfile\Documents\MyCerts";$CertStorePublic=$CertStore + "\Public";$CertStorePrivate=$CertStore + "\Private"
       $CertStoreCSR=$CertStore + "\CSR"
       $AESPath = "$CertStore\AES"; $AESKeyPath="$CertStore\AES\Type-001.TeeStar";$CertEncStore=$CertStore + "\Enc"
    # Cert Variables
       $CertIssuerMatch="CryptoStudio_RooTCA";$CertSub="PS-Crypto_SubCa";$Count=1
       $FriendlyName += "-CryptoStudio"

       $Issuer= "PS-CryptoStudio"
       $Certs=Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object {$_.Issuer -match $Issuer} 
       $Certs | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue| Out-Null
       Get-ChildItem $CertStorePrivate |Where-Object {($_.Name -match "PS-Crypto_RootCert.Pfx") -or ($_.Name -match "PS-Crypto_SubCert01.Pfx") -or ($_.Name -match "PS-Crypto_SubCert02.Pfx")  } | Remove-Item -Force
    }

Function Get-CertInfo 
    {
     <#
	.SYNOPSIS
             Gets certificate information
             Version 1.0.0.4

    .DESCRIPTION
             Gets certificate information from pfx file and returns certificate validity, Subject Name, SAN, Signature Hash Algorithm, Keysize and Issuer. Returns false on errors

    .EXAMPLE
		     PS> Get-Certinfo "C:\Users\User-01\Documents\MyCerts\Private\MyCert.Pfx"

    .INPUTS
		     None.

    .OUTPUTS
             System.Array

    .NOTES
		     Requirements: Windows 10 17.09 or better or Server 2016 or better
       Requirements: Windows PowerShell 5.1
            
    #>  
     [CmdletBinding()]
    Param(
       [Parameter(Mandatory=$True)]       
       [String]$FilePath
       )
     Try
        {
         $Cert=Get-PfxCertificate -FilePath $FilePath -ErrorAction Stop
         $SANRaw=($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "
         $Info= @{
                  CertNotBefore          = $Cert.NotBefore
                  CertNotAfter           = $Cert.NotAfter
                  Subject                = $Cert.Subject
                  SAN                    = $SANRaw
                  SignatureHashAlgorithm = $Cert.SignatureAlgorithm.FriendlyName
                  PublicKeyExchange      = $Cert.PublicKey.Key.KeyExchangeAlgorithm
                  PublicKeySize          = $Cert.PublicKey.Key.KeySize
			      Issuer                 = $Cert.Issuer

         }
        # Sort Hashtable 
         $Info=$Info.GetEnumerator() | Sort-Object -Property name
         Return $Info
        }
     Catch
        {
         Return $false
        }
    }