# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.3
$Invoke_Expression_Override = @'
function Invoke-Expression()
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
        Write-Host $Command
        Microsoft.PowerShell.Utility\Invoke-Expression $Command
    }
'@

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.3
$Invoke_Command_Override = @'
function Invoke-Command ()
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
        Write-Host "%#[Invoke-Command] Execute/Open: $($Command)%#"
        Microsoft.PowerShell.Core\Invoke-Command $Command
    }
'@

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-item?view=powershell-7.3
$Invoke_Item_Override = @'
function Invoke-Item()
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Item
        )
        Write-Host "%#[Invoke-Item] Execute/Open: $($Item)%#"
        Microsoft.PowerShell.Management\Invoke-Item $Item
    }
'@

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item?view=powershell-7.3
$Get_Item_Override = @'
function Get-Item
    {
        Microsoft.PowerShell.Management\Get-Item $args
    }
'@

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item?view=powershell-7.3
$New_Object_Override = @'
function new-object {
        param(
            [Parameter(Mandatory=$True, Valuefrompipeline = $True)]
            [string]$Obj,
            [Parameter(Mandatory=$False)][System.Object[]]$Args
        )
        if($Obj -ieq 'System.Net.WebClient' -or $Obj -ieq 'Net.WebClient'){
            $webclient_obj = microsoft.powershell.utility\new-object Net.WebClient
            Add-Member -memberType ScriptMethod -InputObject $webclient_obj -Force -Name "DownloadFile" -Value {
                param([string]$url,[string]$destination)
                Write-Host "%#[System.Net.WebClient.DownloadFile] Download From: $($url) --> Save To: $($destination) %#"
                }
            Add-Member -memberType ScriptMethod -InputObject $webclient_obj -Force -Name "DownloadString" -Value {
                param([string]$url)
                Write-Host "%#[System.Net.WebClient.DownloadString] Download From: $($url) %#"
                }
            return $webclient_obj
        }
        elseif ($Obj -ieq 'System.Net.Sockets.TCPClient') {
            $tcpclient_obj = microsoft.powershell.utility\new-object System.Net.Sockets.TCPClient
            $IP = $Args[0]
            $port = $Args[1]
            Write-Host "%#[System.Net.Sockets.TCPClient] Connect To $($IP):$($port)%#"
            return $tcpclient_obj
        }
        elseif($Obj -ieq 'random'){
            $random_obj = microsoft.powershell.utility\new-object Random
            Add-Member -memberType ScriptMethod -InputObject $random_obj -Name "next" -Value {
                param([int]$min,[int]$max)
                $random_int = Get-Random -Minimum $min -Maximum $max
                Write-Host "%#[System.Random] Generate random integer between $($min) and $($max). Value returned: $($random_int)%#"
                return $random_int
                }
            return $random_obj
        }
        else {
            if ($Args.count -gt 0) {
                $unk_obj = microsoft.powershell.utility\new-object $Obj $Args
            }
            else {
                $unk_obj = microsoft.powershell.utility\new-object $Obj
            }
            return $unk_obj
        }
    }
'@

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/start-sleep?view=powershell-7.3
$Start_Sleep_Override = @'
function Start-Sleep {
        Write-Host "%#[Start-Sleep] $($args)%#"
    }
'@

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/start-job?view=powershell-7.3
$Start_Job_Override = @'
function start-job {
        param(
            [Parameter(Mandatory=$True, Valuefrompipeline = $True)][ScriptBlock]$ScriptBlock
        )
        Write-Host "$ScriptBlock"
    }
'@

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/receive-job?view=powershell-7.3
$Receive_Job_Override = @'
function receive-job {}
'@

# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill
$Task_Kill_Override = @'
function taskkill {
    Write-Host "%#[taskkill] $($args)%#"
}
'@

# https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems
$Net_Override = @'
function net {
    Write-Host "%#[net] $($args)%#"
}
'@

# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc754599(v=ws.11)
$SC_Override = @'
function sc {
    Write-Host "%#[sc] $($args)%#"
}
'@

# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/start
$Start_Override = @'
function start {
    # In case the array contains subarrays
    $argString = ""
    ForEach($arg in $args) {
        if ($arg.GetType() -eq [System.Object[]]) {
            $argString = $argString + $arg -join " "
        }
        else {
            $argString = $argString + $arg + " "
        }
    }

    Write-Host "%#[start] $($argString)%#"
}
'@

# https://learn.microsoft.com/en-us/powershell/module/servermanager/uninstall-windowsfeature?view=windowsserver2022-ps
$Uninstall_WindowsFeature_Override = @'
function Uninstall-WindowsFeature {
    Write-Host "%#[Uninstall-WindowsFeature] $($args)%#"
}
'@

# https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
$Set_MpPreference_Override = @'
function Set-MpPreference {
    Write-Host "%#[Set-MpPreference] $($args)%#"
}
'@

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7.3
$Start_Process_Override = @'
function Start-Process {
    Write-Host "%#[Start-Process] $($args)%#"
}
'@

# This method writes a fake file to disk
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.3
$Invoke_WebRequest_With_Fake_File_Override = @'
function Invoke-WebRequest {
    # Odds are the first or last arg is the URI, but we'll confirm this later
    if ($args[0].IndexOf("-") -eq -1 -or $args[0].IndexOf("-") -ne 0) {
        $uri = $args[0]
    }
    else {
        $uri = $args[-1]
    }
    $outfile = ""

    # We only care about URI and OutFile
    $nextArgIsUri = $false;
    $nextArgIsOutFile = $false;

    ForEach($arg in $args){
        if ($nextArgIsUri) {
            $uri = $arg
            $nextArgIsUri = $false
        } elseif ($nextArgIsOutFile) {
            $outfile = $arg
            $nextArgIsOutFile = $false;
        }

        if ($arg.GetType() -eq [System.String] -and $arg -ieq "-Uri") {
            $nextArgIsUri = $true
        }
        elseif ($arg.GetType() -eq [System.String] -and ($arg -ieq "-O" -or $arg -ieq "-outf" -or $arg -ieq "-OutFile")) {
            $nextArgIsOutFile = $true
        }
    }

    # If there are no spaces or protocol string in the uri string, add the default
    if ($uri.IndexOf(" ") -eq -1 -and $uri.IndexOf("://") -eq -1) {
        $uri = "http://$($uri)"
    }

    if ($outfile) {
        # We should create a fake file for further execution

        # Create the fake file
        $currdir = "./"
        $file_to_create = Join-Path -Path $currdir -ChildPath $outfile.Replace("\\", "/").Replace("%", "")
        New-Item -ItemType "File" -Path $file_to_create -Force | Out-Null

        # Create the fake content
        $fake_content = "MZ"
        For($ii = 0; $ii -lt 2000; $ii++) {
            $fake_content = $fake_content + "Dummy content, This program cannot be run in DOS mode.`r`n"
        }
        $fake_content | Set-Content $file_to_create

        Write-Host "%#[Invoke-WebRequest] Download From: $($uri) --> Save To: $($outfile) %#"
    } else {
        Write-Host "%#[Invoke-WebRequest] Download From: $($uri) %#"
    }
}
'@

# This method does not write a fake file to disk
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.3
$Invoke_WebRequest_Override = @'
function Invoke-WebRequest {
    # Odds are the first or last arg is the URI, but we'll confirm this later
    if ($args[0].IndexOf("-") -eq -1 -or $args[0].IndexOf("-") -ne 0) {
        $uri = $args[0]
    }
    else {
        $uri = $args[-1]
    }
    $outfile = ""

    # We only care about URI and OutFile
    $nextArgIsUri = $false;
    $nextArgIsOutFile = $false;

    ForEach($arg in $args){
        if ($nextArgIsUri) {
            $uri = $arg
            $nextArgIsUri = $false
        } elseif ($nextArgIsOutFile) {
            $outfile = $arg
            $nextArgIsOutFile = $false;
        }

        if ($arg.GetType() -eq [System.String] -and $arg -ieq "-Uri") {
            $nextArgIsUri = $true
        }
        elseif ($arg.GetType() -eq [System.String] -and ($arg -ieq "-O" -or $arg -ieq "-outf" -or $arg -ieq "-OutFile")) {
            $nextArgIsOutFile = $true
        }
    }

    # If there are no spaces or protocol string in the uri string, add the default
    if ($uri.IndexOf(" ") -eq -1 -and $uri.IndexOf("://") -eq -1) {
        $uri = "http://$($uri)"
    }

    # Even if we don't actually write a file, it is nice to log what would have happened
    if ($outfile) {
        Write-Host "%#[Invoke-WebRequest] Download From: $($uri) --> Save To: $($outfile) %#"
    } else {
        Write-Host "%#[Invoke-WebRequest] Download From: $($uri) %#"
    }
}
'@

function Get_Encoding_Type {
    param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$input_bytes
        )

    $enc_type = ''
    if($input_bytes[0] -eq 0xEF -and $input_bytes[1] -eq 0xBB -and $input_bytes[2] -eq 0xBF){
        $enc_type = 'UTF8'
        }
    elseif($input_bytes[0] -eq 0xFE -and $input_bytes[1] -eq 0xFF){
        $enc_type = 'UTF16-BE-BOM'
        }
    elseif($input_bytes[0] -eq 0xFF -and $input_bytes[1] -eq 0xFE){
        $enc_type = 'UTF16-LE-BOM'
        }
    elseif($input_bytes[1] -eq 0x00 -and $input_bytes[3] -eq 0x00 -and $input_bytes[5] -eq 0x00 -and $input_bytes[7] -eq 0x00 `
      -and $input_bytes[0] -ne 0x00 -and $input_bytes[2] -ne 0x00 -and $input_bytes[4] -ne 0x00 -and $input_bytes[6] -ne 0x00){
        $enc_type = 'UTF16-LE'
        }
    elseif($input_bytes[0] -eq 0x00 -and $input_bytes[2] -eq 0x00 -and $input_bytes[4] -eq 0x00 -and $input_bytes[6] -eq 0x00 `
      -and $input_bytes[1] -ne 0x00 -and $input_bytes[3] -ne 0x00 -and $input_bytes[5] -ne 0x00 -and $input_bytes[7] -ne 0x00){
        $enc_type = 'UTF16-BE'
        }
    else {
        $enc_type = 'ASCII'
        }
    return $enc_type
}

function Base64_Encode{
    param(
            [Parameter(Mandatory=$True)]
            [String[]]$str
           )

    $Bytes = [System.Text.Encoding]::UNICODE.GetBytes($str)
    $EncodedText =[Convert]::ToBase64String($Bytes)
    return $EncodedText
}

function Base64_Decode {
    param(
        [Parameter(Mandatory=$True)]
        [String[]]$b64_encoded_string
       )

    # This clause is for converting base64-encoded executables
    if($b64_encoded_string -match '^TVqQ'){
        return [Byte[]][Convert]::FromBase64String($b64_encoded_string)
    }

    try{
        $b64_decoded = [System.Convert]::FromBase64String($b64_encoded_string)
        }
    catch{
        $ErrorMessage = $_.Exception.Message
        Write-Verbose "$($ErrorMessage)"
        return $false
    }

    $b64_decoded_ascii = [System.Text.Encoding]::ASCII.GetString($b64_decoded)
    if($b64_decoded_ascii -match '^(.\x00){8,}'){
        return [System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String($b64_encoded_string))
    }
    else{
        return $b64_decoded_ascii
    }
}

function Replace_Quotes_FuncName
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       $str_format_pattern = [regex]"[\.&](\`"|')[a-zA-Z0-9]+(\`"|')\("
       $matches = $str_format_pattern.Matches($Command)

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                Write-Verbose "[Replace_Quotes_FuncName] Replacing: $($match) With: $($match.ToString().replace('"', '').replace("'", ''))"
                $Command = $Command.Replace($match, $match.ToString().replace('"','').replace("'",""))
                }
            $matches = $str_format_pattern.Matches($Command)
        }

       return $Command

    }

function Replace_FuncParensWrappers
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       $str_format_pattern = [regex]"[\.&]\(('|`")[a-zA-Z-]+('|`")\)"
       $matches = $str_format_pattern.Matches($Command)

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                Write-Verbose "[Replace_FuncParensWrappers] Replacing: $($match)`tWith: $($match.ToString().replace('.','').replace('&','').replace("('",'').replace("')",'').replace('("','').replace('")',''))"
                $Command = $Command.Replace($match, $match.ToString().replace('.','').replace('&','').replace("('",'').replace("')",'').replace('("','').replace('")',''))
                }
            $matches = $str_format_pattern.Matches($Command)
        }

       return $Command

    }

function Clean_Func_Calls
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )

       $str_format_pattern = [regex]"\.['`"][a-zA-Z0-9``]+['`"]"
       $matches = $str_format_pattern.Matches($Command)

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                $replaced_val = $match.ToString().replace('"','').replace("'",'').replace("``",'')
                Write-Verbose "[Clean_Func_Calls] Replacing: $($match) With: $($replaced_val)"
                $Command = $Command.Replace($match, $replaced_val )
                }
            $matches = $str_format_pattern.Matches($Command)
        }

       return $Command

    }

function Replace_Parens
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       $str_format_pattern = [regex]"[^a-zA-Z0-9.&()]\(\s*'[^']*'\)"
       $matches = $str_format_pattern.Matches($Command)

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                Write-Verbose "[Replace_Parens] Replacing: $($match) With: $($match.ToString().replace('(','').replace(')',''))"
                $Command = $Command.Replace($match, $match.ToString().replace('(','').replace(')',''))
                }
            $matches = $str_format_pattern.Matches($Command)
        }

       return $Command

    }

function Replace_NonEscapes
    {
        param(
            [Parameter(Mandatory=$True)]
            [char[]]$Command
        )

        $prev_char = ''
        $new_str = ''
        $in_str = $false
        $curr_quote_chr = ''
        $str_quotes = '"', "'"
        $char_idx_arr = @()
        $special_chars = "0", "a", "b", "f", "n", "r", "t", "v", "'", "``", "`#", '"'
        $special_chars = "0", "a", "b", "f", "n", "r", "v", "'", "``", "`#", '"'
        for ($char=0; $char -lt $Command.Length; $char++){
            if($Command[$char] -in $str_quotes -and -not $in_str){
                $curr_quote_chr=$Command[$char]
                $in_str = $true
            }
            elseif($Command[$char] -in $str_quotes -and $in_str -and $Command[$char] -eq $curr_quote_chr  -and $prev_char -ne '`'){
                $curr_quote_chr=''
                $in_str = $false
            }
            elseif($Command[$char] -eq '`' -and -not $in_str){
                $char_idx_arr += ,$char
            }
            elseif($prev_char -eq '`' -and $in_str -and $Command[$char] -notin $special_chars){
                $char_idx_arr += ,$($char-1)
            }
            $prev_char = $Command[$char]
        }

        [System.Collections.ArrayList]$newCommand = $Command
        $idx_offset = 0

        if($char_idx_arr.Length -gt 0){
            Write-Verbose "$($char_idx_arr.Length) Non-escape characters detected... Removing"
            }

        ForEach($idx in $char_idx_arr){
            $newCommand.RemoveAt($idx-$idx_offset)
            $idx_offset++
        }

    return $newCommand -join ''
}

function Replace_MultiLineEscapes
    {
        param(
            [Parameter(Mandatory=$True)]
            [string]$Command
        )

        $str_format_pattern = [regex]'`\s*\r\n\s*'
        $matches = $str_format_pattern.Matches($Command)

        While ($matches.Count -gt 0){
            if($matches.Count -gt 0){
                Write-Verbose "$($matches.Count) instances of multi-line escape characters detected... Removing"
            }
            ForEach($match in $matches){

                $Command = $Command.Replace($match, ' ')
                }
            $matches = $str_format_pattern.Matches($Command)
        }
    return $Command
}

# In PowerShell on Linux, wget is the command for the Wget tool https://www.gnu.org/software/wget/
# But in PowerShell on Windows, wget is an alias for the Invoke-WebRequest commandlet
function Replace_Wget
    {
        param(
            [Parameter(Mandatory=$True)]
            [string]$Command
        )

        $wget_pattern = [regex]'(?i)\bwget\b'
        $matches = $wget_pattern.Matches($Command)

        While ($matches.Count -gt 0){
            if($matches.Count -gt 0){
                Write-Verbose "$($matches.Count) instances of wget detected... Replacing!"
            }
            ForEach($match in $matches){
                $Command = $Command.Replace($match, 'Invoke-WebRequest')
            }
            $matches = $wget_pattern.Matches($Command)
        }
    return $Command
}

function Resolve_Env_Variables
    {
        param(
            [Parameter(Mandatory=$True)]
            [string]$Command
        )

        $env_pattern = [regex]'(?i)\$env\:\b\w+\b'
        $matches = $env_pattern.Matches($Command)

        While ($matches.Count -gt 0){
            if($matches.Count -gt 0){
                Write-Verbose "$($matches.Count) instances of `$env:<variable-name>` detected... Replacing!"
            }
            ForEach($match in $matches){
                $Command = $Command.Replace($match, './')
            }
            $matches = $env_pattern.Matches($Command)
        }
    return $Command
}

function Resolve_String_Formats
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       $str_format_pattern = [regex]"\(`"({\d+})+`"\s*-[fF]\s*(('[^']*'|\('[^']*'\))\s*,?\s*)*\)"
       #$str_format_pattern = [regex]"\(`"({\d+})+`"\s*-[fF]\s*('[^']*',?)+\)"
       $matches = $str_format_pattern.Matches($Command)

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                $resolved_string = IEX($match)
                $Command = $Command.Replace($match, "'$($resolved_string)'")
                $truncated = $false;
                $match = "$($match)"
                if ($match.Length -gt 500) {
                    $truncated = $true;
                    $match = $match.substring(0, 500)
                }
                if ($resolved_string.Length -gt 500) {
                    $truncated = $true;
                    $resolved_string = $resolved_string.substring(0, 500)
                }
                if ($truncated) {
                    Write-Verbose "[Resolve_String_Formats] Replacing: $($match)... With: $($resolved_string)..."
                }
                else {
                    Write-Verbose "[Resolve_String_Formats] Replacing: $($match) With: $($resolved_string)"
                }
            }
            $matches = $str_format_pattern.Matches($Command)
        }

       return $Command
    }

function Resolve_Replaces
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )

        $str_format_pattern = [regex]"(?i)\(?['`"][^'`"]+['`"]\)?\.replace\((?:(?:'.+?')|(?:[^,]+)),(?:(?:'.+?')|(?:[^\)]+))\)"
        $matches = $str_format_pattern.Matches($Command)
        While ($matches.Count -gt 0){
            ForEach($match in $matches){
                Write-Verbose "match: $match"
                try {
                    $resolved_string = IEX($match)
                }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-Verbose "$($ErrorMessage)"
                    continue
                }
                $resolved_string = $resolved_string.replace("'","''")
                Write-Verbose "[Resolve_Replaces] Replacing: $($match) With: $($resolved_string)"
                $Command = $Command.Replace($match, "'$($resolved_string)'")
            }
            $matches = $str_format_pattern.Matches($Command)
        }

       return $Command
    }

function Resolve_PowerShell_On_Linux
{
    param(
        [Parameter( `
            Mandatory=$True, `
            Valuefrompipeline = $True)]
        [String]$Command
    )

    $env_windir_pattern = [regex]'(?i)\$env\:windir'
    $matches = $env_windir_pattern.Matches($Command)
    While ($matches.Count -gt 0){
        ForEach($match in $matches){
            $resolved_string = "'/usr/bin/pwsh'"
            Write-Verbose "[Resolve_PowerShell_On_Linux] Replacing: $($match) With: '$($resolved_string)'"
            $Command = $Command.Replace($match, "$($resolved_string)")
        }
        $matches = $env_windir_pattern.Matches($Command)
    }

    $powershell_path_pattern = [regex]"(?i)\\syswow64\\windowspowershell\\v1\.0\\powershell\.exe"
    $matches = $powershell_path_pattern.Matches($Command)
    While ($matches.Count -gt 0){
        ForEach($match in $matches){
            $resolved_string = ""
            Write-Verbose "[Resolve_PowerShell_On_Linux] Replacing: $($match) With: '$($resolved_string)'"
            $Command = $Command.Replace($match, "$($resolved_string)")
        }
        $matches = $powershell_path_pattern.Matches($Command)
    }

    # Since we are already using Linux's pwsh to run the script, we do not need a redundant powershell image path
    $powershell_image_pattern = [regex]"(?i)powershell(\.exe)?\s*"
    $matches = $powershell_image_pattern.Matches($Command)
    While ($matches.Count -gt 0){
        ForEach($match in $matches){
            $resolved_string = ''
            Write-Verbose "[Resolve_PowerShell_On_Linux] Replacing: $($match) With: '$($resolved_string)'"
            $Command = $Command.Replace($match, "$($resolved_string)")
        }
        $matches = $powershell_image_pattern.Matches($Command)
    }

    return $Command
}

function Resolve_Windows_Directories_On_Linux
    {
    param(
        [Parameter( `
            Mandatory=$True, `
            Valuefrompipeline = $True)]
        [String]$Command
    )
    $currdir = "./"
    $windir_pattern = [regex]'(?i)((?:[a-zA-Z]:|%\w+%)\\(?:\w+\\)*)\w+\.\w+'
    $matches = $windir_pattern.Matches($Command)
    ForEach($match in $matches){
        # Convert \\ -> / and remove % and join the path to the present working directory
        $resolved_string = Join-Path -Path $currdir -ChildPath $match.groups[0].Value.Replace("\\", "/").Replace("%", "")
        $directory_to_create = Join-Path -Path $currdir -ChildPath $match.groups[1].Value.Replace("\\", "/").Replace("%", "")
        if (-not (Test-Path $directory_to_create)) {
            Write-Verbose "Creating $($directory_to_create)"
            New-Item -ItemType "Directory" -Path $directory_to_create | Out-Null
        }

        Write-Verbose "[Resolve_Windows_Directories_On_Linux] Replacing: $($match) With: '$($resolved_string)'"
        $Command = $Command.Replace($match, "$($resolved_string)")
    }
    return $Command
}

function Remove_Unusable_Args_On_Linux
    {
    param(
        [Parameter( `
            Mandatory=$True, `
            Valuefrompipeline = $True)]
        [String]$Command
    )

    $unusable_args_pattern = [regex]'(?i)(bypass|hidden|-(?:noprofile|windowstyle|executionpolicy))\b'
    $matches = $unusable_args_pattern.Matches($Command)
    ForEach($match in $matches){
        Write-Verbose "[Remove_Unusable_Args_On_Linux] Removing: $($match)"
        $Command = $Command.Replace($match, "")
    }
    return $Command
}

function Remove_String_Concat
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       return $Command.Replace("'+'", "").Replace('"+"','')
    }

function Remove_Carets
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       return $Command.Replace("^", "")
    }

function Resolve_Background_Tasks
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
        $background_task_pattern = [regex]'(?i)\b(\s*&\s*)start'
        $matches = $background_task_pattern.Matches($Command)
        ForEach($match in $matches){
            Write-Verbose "[Resolve_Background_Tasks] Replacing: $($match.groups[1]) with a newline character"
            $Command = $Command.Replace($match.groups[1], "`r`n")
        }
        return $Command
    }

function Code_Cleanup
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )

       $old_command = ''
       $new_command = $Command

       While($old_command -ne $new_command)
       {
            $old_command = $new_command

            $new_command = Replace_MultiLineEscapes($new_command)
            $new_command = Replace_NonEscapes($new_command)
            $new_command = Replace_Quotes_FuncName($new_command)
            $new_command = Clean_Func_Calls($new_command)
            $new_command = Replace_Parens($new_command)
            $new_command = Replace_FuncParensWrappers($new_command)
            $new_command = Remove_String_Concat($new_command)
            $new_command = Resolve_String_Formats($new_command)
            $new_command = Resolve_Replaces($new_command)
            $new_command = Resolve_PowerShell_On_Linux($new_command)
            $new_command = Resolve_Windows_Directories_On_Linux($new_command)
            $new_command = Remove_Unusable_Args_On_Linux($new_command)
            $new_command = Remove_Carets($new_command)
            $new_command = Resolve_Background_Tasks($new_command)
            $new_command = Replace_Wget($new_command)
            $new_command = Resolve_Env_Variables($new_command)
        }

        return $new_command

    }

function Beautify
    {
        param(
            [Parameter(Mandatory=$True)]
            [char[]]$Command
        )
        $prev_char = ''
        $tabs = 0
        $tab = "`t"
        $newline = "`r`n"
        $new_str = ''
        $in_str = $false
        $curr_quote_chr = ''
        $str_quotes = '"', "'"
        $append_chars = ''

        forEach($char in $Command){
            if($char -contains $str_quotes -and $in_str -eq $false){
                $curr_quote_chr=$char
                $in_str = $true
            }
            elseif($char -contains $str_quotes -and $in_str -eq $true -and $curr_quote_chr -eq $char -and $prev_char -ne '`'){
                $curr_quote_chr=''
                $in_str = $false
            }
            elseif($char -eq '{' -and $in_str -eq $false){
                $append_chars = $newline + ($tab*++$tabs)
            }
            elseif($char -eq '}' -and $in_str -eq $false){
                $append_chars = $newline + ($tab*--$tabs)
            }
            elseif($char -eq ';' -and $in_str -eq $false){
                $append_chars = $newline + ($tab*$tabs)
            }

            $new_str = $new_str + $char + $append_chars
            $prev_char = $char
            $append_chars = ''
        }
    return $new_str
}

function Get_SHA256
    {
        param(
            [Parameter(Mandatory=$True)]
            [byte[]]$strBytes
        )

        $sha256obj = new-object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider
        $hash = [System.BitConverter]::ToString($sha256obj.ComputeHash($strBytes))

        return $hash.ToLower().Replace('-','')
    }

function Extract_Executables {
    param(
            [Parameter(Mandatory=$True)][String]$dump,
            [Parameter(Mandatory=$True)][System.Text.RegularExpressions.MatchCollection]$exe_pattern_matches
         )

    $count = 0
    forEach($match in $exe_pattern_matches) {
        $b64_decoded = Base64_Decode($match)
        if (!$b64_decoded) {
            continue
        }
        $out_filename = "$dump/psdecode_executable_$($count).bin"
        if ($PSVersionTable.PSVersion.Major -gt 6) {
            $b64_decoded | Set-Content $out_filename -AsByteStream
        }
        else {
            $b64_decoded | Set-Content $out_filename -Encoding Byte
        }
        Write-Verbose "Writing $($out_filename)"
        $count += 1
    }
}

function Dump_Files {
    param(
            [Parameter(Mandatory=$True)][System.Collections.Generic.List[System.Object]]$layers,
            [Parameter(Mandatory=$True)][String]$dump
         )

    $layer_count = 0
    ForEach ($layer in $layers)
        {
            $layer = $layer.Trim()
            $out_filename = "$dump/layer_$($layer_count).ps1"
            $layer | Out-File $out_filename -NoNewline
            Write-Verbose "Writing $($out_filename)"
            $layer_count += 1
        }

    if($beautify)
        {
            $out_filename = "$dump/layer_$($layers.count + 1).ps1"
            Beautify($str_fmt_res) | Out-File $out_filename -NoNewline
            Write-Verbose "Writing $($out_filename)"
        }

    $exe_str_format_pattern = [regex]"TVqQ[^'`"]{100,}"
    $exe_matches = $exe_str_format_pattern.Matches($layers[-1])

    if($exe_matches.Count -gt 0)
        {
            Write-Verbose "Identified $($exe_matches.Count) potential executable(s)"
            $extracted_exes = Extract_Executables $dump $exe_matches
        }
}

function PSDecode {
<#
.SYNOPSIS
    Obfuscated PowerShell Script Decoder
.Description
    This is a PowerShell script for deobfuscating other encoded PowerShell scripts. Often, malicious PowerShell scripts have several layers of encodings (Replace, Base64Decode, etc...) that, once decoded, are executed via a call to Invoke-Expression (IEX, &, .), Invoke-Command, etc... This script employs a technique called method overriding that enables us to essentially intercept calls to functions that I have accounted for within this script and print out the arguments being passed to it (a.k.a what the script was trying to execute).

    ** Important Note: It is highly recommended that you only run this script within an isolated sandbox. If the encoded powershell attempts to execute a function which I have not accounted for, there is a chance it could execute.**

.PARAMETER verbose
    PSDecode will describe in greater detail what it is doing during the decoding process. Can be helpful when troubleshooting

.PARAMETER dump
    PSDecode will dump all of the decoded layers to the path passed in. Filename will be in the format layer_<layer_number>.ps1.
    For example:
                layer_1.ps1
                layer_2.ps1
                layer_3.ps1

.PARAMETER beautify
    Attempts to beautify the final layer. This typically works well on simpler scripts but might break on more complex scripts. As a result, I've made this optional.

.PARAMETER x
    Disables the New-Object override. Should only be tried if standard decoding without this switch fails, which is typically the case when PSDecode encounters object arrays. Setting this switch is risky as there is significantly higher likelihood of malicious code execution. Should only be used in an isolated environment.

.PARAMETER timeout
    Sets the maximum number of seconds the decoder should be allowed to run before it is timed out and terminated. Default is 60 seconds.

.PARAMETER fakefile
    Indicates if we want a web request to write a fake file to disk. Default is false.

.NOTES
    File Name  : PSDecode.psm1
    Author     : @R3MRUM
    Version    : 5.0
.LINK
    https://github.com/R3MRUM/PSDecode
.LINK
    https://twitter.com/R3MRUM
.LINK
    https://r3mrum.wordpress.coom
.EXAMPLE
    PSDecode -verbose -dump -beautify -fakefile .\encoded_ps.ps1

.EXAMPLE
    Get-Content .\encoded_ps.ps1 | PSDecode
.COMPONENT
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][String]$dump,
        [Parameter(Mandatory=$false)][switch]$beautify,
        [Parameter(Mandatory=$false)][switch]$x,
        [Parameter(Mandatory=$false)][int]$timeout = 60,
        [Parameter(Mandatory=$false)][switch]$fakefile,
        [Parameter(Mandatory=$True, Valuefrompipeline = $True, Position = 0)][PSObject[]]$InputObject
    )
    $layers  = New-Object System.Collections.Generic.List[System.Object]
    $actions = New-Object System.Collections.Generic.List[System.Object]
    $action_pattern = [regex]'%#\[([^\]]+)\]\s(.+?)%#'

    $override_functions = @()
    $encoded_script = ""

    if($timeout -ne 60) {
        Write-Verbose "Default timeout of 60 seconds changed to $($timeout)"
    }

    try {
        if($IsLinux -or $IsMacOs){
            $script_bytes = Get-Content $InputObject -Raw -AsByteStream -ErrorAction Stop
        }
        else{
            $script_bytes = Get-Content $InputObject -Raw -Encoding byte -ErrorAction Stop
        }
    }
    catch {
            $ErrorMessage = $_.Exception.Message
            Write-Verbose "$($ErrorMessage)"
            throw "Error reading: $($InputObject)"
        }

    $sha256 = Get_SHA256($script_bytes)
    $enc_type = Get_Encoding_Type($script_bytes)
    $pref_enc = [System.Text.Encoding]::ASCII

    if($enc_type -eq 'UTF16-LE' ){
        $encoded_script = [System.Text.Encoding]::UNICODE.GetString($script_bytes)
    }
    elseif($enc_type -eq 'UTF16-BE' ){
        $encoded_script = [System.Text.Encoding]::BigEndianUnicode.GetString($script_bytes)
    }
    elseif($enc_type -eq 'UTF16-LE-BOM' ){
        $encoded_script = [System.Text.Encoding]::UNICODE.GetString($script_bytes).substring(2)
    }
    elseif($enc_type -eq 'UTF16-BE-BOM' ){
        $encoded_script = [System.Text.Encoding]::BigEndianUnicode.GetString($script_bytes).substring(2)
    }
    elseif($enc_type -eq 'UTF8'){
        $encoded_script = [System.Text.Encoding]::UTF8.GetString($script_bytes).substring(1)
        }
    else{
        $encoded_script = [System.Text.Encoding]::ASCII.GetString($script_bytes)
    }

    $b64_decoded = Base64_Decode($encoded_script.Trim())

    if($b64_decoded){
        $encoded_script = $b64_decoded
    }

    $override_functions += $Invoke_Expression_Override
    $override_functions += $Invoke_Command_Override
    $override_functions += $Invoke_Item_Override
    $override_functions += $Get_Item_Override
    $override_functions += $Start_Sleep_Override
    $override_functions += $Start_Job_Override
    $override_functions += $Receive_Job_Override
    $override_functions += $Task_Kill_Override
    $override_functions += $Net_Override
    $override_functions += $SC_Override
    $override_functions += $Start_Override
    $override_functions += $Uninstall_WindowsFeature_Override
    $override_functions += $Set_MpPreference_Override
    $override_functions += $Start_Process_Override

    if(!$x){
        $override_functions += $New_Object_Override
    }

    if($fakefile){
        $override_functions += $Invoke_WebRequest_With_Fake_File_Override
    } else {
        $override_functions += $Invoke_WebRequest_Override

    }


    $override_functions  = ($override_functions -join "`r`n") + "`r`n`r`n"

    Write-Verbose "Original file hash: $(Get_SHA256([System.Text.Encoding]::UNICODE.GetBytes($encoded_script)))"
    $original_script = $encoded_script
    $clean_code = Code_Cleanup($encoded_script)

    if($encoded_script -ne $clean_code){
        $encoded_script = $clean_code
    }

    $decoder = $override_functions + $encoded_script
    $b64_decoder = Base64_Encode($decoder)

    while($layers -notcontains ($encoded_script) -and -not [string]::IsNullOrEmpty($encoded_script)){
        $encoded_script_hash = Get_SHA256([System.Text.Encoding]::UNICODE.GetBytes($encoded_script))
        Write-Verbose "Running $($encoded_script_hash)"
        if ($encoded_script -ne $original_script) {
            Write-Verbose "Adding $($encoded_script_hash) to layers"
            $layers.Add($encoded_script)
        }

        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "pwsh"
        $pinfo.CreateNoWindow = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false

        if($b64_decoder.length -le 8000){
            $pinfo.Arguments = "-EncodedCommand $($b64_decoder)"
        }
        else{
            $tmp_file = [System.IO.Path]::GetTempPath() + [GUID]::NewGuid().ToString() + ".ps1";
            Base64_Decode($b64_decoder) | Out-File $tmp_file
            $pinfo.Arguments = "-File $($tmp_file)"
        }

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        Write-Verbose "Started process with encoded file..."

        # Read stdin\stdout synchronously
        # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.standardoutput?view=net-7.0
        $encoded_script = $p.StandardOutput.ReadToEnd()

        # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.waitforexit?view=net-7.0
        if(-not $p.WaitForExit($timeout*1000)){
            Write-Host -ForegroundColor Red "$($timeout) second timeout hit when executing decoder. Killing process and breaking out"
            Stop-Process $p
            if ($tmp_file -and (Test-Path $tmp_file)){
                Remove-Item $tmp_file
            }
            break
        }

        Write-Verbose "Process has finished..."

        $stderr = $p.StandardError.ReadToEnd()

        if ($tmp_file -and (Test-Path $tmp_file)){
            Remove-Item $tmp_file
        }

        $action_matches = $action_pattern.Matches($encoded_script)

        if($p.ExitCode -eq 0 -and $encoded_script -and $action_matches.Count -eq 0){
            $encoded_script = Code_Cleanup($encoded_script)
            $decoder = ($override_functions -join "`r`n`r`n") + "`r`n`r`n" + $encoded_script
            $b64_decoder = Base64_Encode($decoder)
        }
        ElseIf($p.ExitCode -eq 0 -and $action_matches.Count -gt 0){
            Write-Verbose 'Final layer processed. Successful exit with actions detected'
            ForEach($action in $action_matches){
                $action_detected = ($action.ToString().Replace('%#','').Trim())
                Write-Verbose "Action detected: $($action.groups[1].Value)"
                $actions.Add($action_detected) | Out-Null
                # Remove? overriden lines
                if ($action.groups.count -eq 3) {
                    Write-Verbose "Replacing action '$($action.groups[0].Value)' with ''"
                    $encoded_script = $encoded_script.Replace($action.groups[0].Value, "").Trim()
                }
            }
            if (-not [string]::IsNullOrEmpty($encoded_script) -and $layers -notcontains ($encoded_script)) {
                $encoded_script_hash = Get_SHA256([System.Text.Encoding]::UNICODE.GetBytes($encoded_script))
                Write-Verbose "Adding $($encoded_script_hash) to layers"
                $layers.Add($encoded_script)
            }
            Break
        }
        ElseIf($p.ExitCode -ne 0 -and $action_matches.Count -gt 0){
            Write-Verbose 'Final layer processed. Non-zero exit code with actions detected'
            ForEach($action in $action_matches){
                $actions.Add($action.ToSring().Replace('%#','').Trim()) | Out-Null
            }
            $err = $true
            Break
        }
        ElseIf($p.ExitCode -ne 0 -and  $action_matches.Count -eq 0){
            Write-Verbose 'Final layer processed. Non-zero exit code without actions detected'
            $err = $true
            Break
        }
     }

    if($layers.Count -gt 0){
        $last_layer = $layers[-1]
        if(-not $noclean){
            $str_fmt_res = Code_Cleanup($last_layer)
        }
        else{
            $str_fmt_res = $last_layer
        }

        if($str_fmt_res -ne $last_layer){
            $layers.Add($str_fmt_res)
        }

        if(-not ([string]::IsNullOrEmpty($dump))){
            Dump_Files $layers $dump
        }

        ForEach ($layer in $layers){
            $heading = "`r`n`r`n" + "#"*30 + " Layer " + ($layers.IndexOf($layer)+1) + " " + "#"*30
            Write-Host $heading
            $layer_lines = $layer -split '\r?\n';
            $layer_line_count = 0
            ForEach ($layer_line in $layer_lines) {
                if ($layer_line_count -gt 100) {
                    # After 100 lines, we get it
                    Write-Host "..."
                    break
                }
                if($layer_line.length -gt 1000) {
                    Write-Host "$($layer_line.substring(0, 1000))..."
                } else {
                    Write-Host $layer_line
                }
                $layer_line_count += 1
            }
        }
    }

    if($p.ExitCode -eq 0){
        if($beautify){
            $beautiful_str = Beautify($str_fmt_res)
            $heading = "`r`n`r`n" + "#"*25 + " Beautified Layer " + "#"*26
            Write-Host $heading
            Write-Host $beautiful_str
        }

        if ($stderr) {
            $heading = "`r`n`r`n" + "#"*30 + " Warning! " + "#"*31
            $footer = "#"*30 + " Warning! " + "#"*31
            Write-Host -ForegroundColor Yellow $heading
            Write-Host -ForegroundColor Yellow "Exit code: $($p.ExitCode)"
            Write-Host -ForegroundColor Yellow "Decoder script returned successful exit code but also sent the following to stderr:`r`n$($stderr)"
            Write-Host -ForegroundColor Yellow $footer
        }

        if($actions.Count -gt 0){
            $heading = "`r`n`r`n" + "#"*30 + " Actions " + "#"*30
            Write-Host $heading
            for ($counter=0; $counter -lt $actions.Count; $counter++){
                $action = "$($actions[$counter])"
                $action_lines = $action -split "`n";
                $action_line_count = 0
                ForEach ($action_line in $action_lines) {
                    if ($action_line_count -gt 100) {
                        # After 100 lines, we get it
                        Write-Host "..."
                        break
                    }
                    if($action_line.length -gt 10000) {
                        Write-Host $action_line.substring(0, 10000) "..."
                    } else {
                        Write-Host $action_line
                    }
                    $action_line_count += 1
                }
            }
        }
    }
    ElseIf($p.ExitCode -ne 0 -and -not $stderr){
        $heading = "`r`n`r`n" + "#"*30 + " Warning! " + "#"*31
        $footer = "#"*30 + " Warning! " + "#"*31
        Write-Host -ForegroundColor Yellow $heading
        Write-Host -ForegroundColor Yellow "Exit code: $($p.ExitCode)"
        Write-Host -ForegroundColor Yellow "Decoder script returned non-zero exit code but no error message was sent to stderr. This is likely the result of the malware intentionally terminating its own execution rather than some kind of decoding failure"
        Write-Host -ForegroundColor Yellow $footer
        }
    ElseIf($p.ExitCode -ne 0 -and $stderr){
        $heading = "`r`n`r`n" + "#"*30 + " Warning! " + "#"*31
        $footer = "#"*30 + " ERROR! " + "#"*31
        Write-Host -ForegroundColor Red -BackgroundColor White $heading
        Write-Host -ForegroundColor Red "Exit code: $($p.ExitCode)"
        Write-Host -ForegroundColor Red $stderr
        Write-Host -ForegroundColor Red -BackgroundColor White $footer
        }

    if($exe_matches.Count -gt 0 -and -not $dump){
        Write-Host -ForegroundColor Yellow "$($exe_matches.Count) possible executable(s) embedded within the encoded script. Rerun PSDecode with -dump switch to attempt to extract"

    }
}
