[CmdletBinding()] Param (
    [Parameter(Mandatory = $True)]
    [String]
    $InFile,
    [String]
    $OutFile,
    [Alias("e")]
    [Switch]
    $Encrypt,
    [Alias("d")]
    [Switch]
    $Decrypt,
    [Alias("k")]
    [Parameter(Mandatory = $True)]
    [String]
    $Key,
    [Alias("m")]
    [String]
    $Mode,
    [Alias("r")]
    [Switch]
    $DecryptReflection,
    [Alias("p")]
    [String]
    $Parameters
)

#Resolve-Path Depresser
If ($PSBoundParameters.ContainsKey('OutFile'))
{
    $OutFile = "$(Get-Location)\$OutFile"
}
$InFile = "$(Get-Location)\$InFile"

function Create-AesManagedObject($key, $IV, $mode) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    if ($PSBoundParameters.ContainsKey('Mode') -eq $False){$mode="CBC"}
    if ($mode="CBC") { $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC }
    elseif ($mode="CFB") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CFB}
    elseif ($mode="CTS") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CTS}
    elseif ($mode="ECB") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB}
    elseif ($mode="OFB"){$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::OFB}


    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($Key) {
        if ($Key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($Key)
        }
        else {
            $aesManaged.Key = $Key
        }
    }
    $aesManaged
}

function Encrypt-String($key, $plaintext) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

Write-Output "Depresser is starting"

If ($Encrypt)
    {
        "Depresser AES $mode Encyption"
        if ($PSBoundParameters.ContainsKey('OutFile') -eq $False)
        {
            Write-Output "OutFile is required"
        }
        $fileBytes=[char[]][Convert]::ToBase64String([IO.File]::ReadAllBytes($InFile))
        $encryptedFile = Encrypt-String $Key $fileBytes
        [IO.File]::WriteAllBytes($OutFile, [char[]]$encryptedFile)

    }
elseif ($Decrypt)
    {
        "Depresser AES $mode Decryption"
        if ($PSBoundParameters.ContainsKey('OutFile') -eq $False)
        {
            Write-Output "OutFile is required"
        }
        $fileString = [char[]][IO.File]::ReadAllBytes($InFile)
        $decryptedFile = Decrypt-String $Key $fileString
        [IO.File]::WriteAllBytes($OutFile, [Convert]::FromBase64String($decryptedFile))
        
    }
elseif ($DecryptReflection) {
    "Depresser AES $mode Decryption with Reflection Assembly"
    $fileString = [char[]][IO.File]::ReadAllBytes($InFile)
    $decryptedFile = Decrypt-String $Key $fileString
    $ms=[Convert]::FromBase64String($decryptedFile)
    $AS = [System.Reflection.Assembly]::Load($ms)
    $mainClass = $AS.EntryPoint.DeclaringType
    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)
    Invoke-Expression "[$mainClass]::Main('$Parameters'.Split())"
    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
}
else
    {
        Write-Output "You should choose mode."
    }

