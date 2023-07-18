#!/usr/bin/env python3
import base64
import binascii
import os
import re
import zlib
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from assemblyline_service_utilities.common.extractor.base64 import base64_search
from Crypto.Cipher import AES

__author__ = "Jeff White [karttoon] @noottrak"
__email__ = "jwhite@paloaltonetworks.com"
__version__ = "1.0.0"
__date__ = "X"


# The garbage_list is used to prevent loops for functions that don't replace content but simply append to existing
garbage_list = list()

DEOBFUS_FILE = "deobfuscated.ps1"

REGEX_INDICATORS = "regex_indicators"
STR_INDICATORS = "str_indicators"

SUSPICIOUS_BEHAVIOUR_COMBO = "Suspicious Behaviour Combo"

#####################
# Support Functions #
#####################


def strip_ascii(content_data):
    """
    Strips out non-printable ASCII chars from strings, leaves CR/LF/Tab.

    Args:
        content_data: b"\x01He\x05\xFFllo"

    Returns:
        stripped_message: "Hello"
    """
    stripped_message = str()

    if type(content_data) == bytes:

        for entry in content_data:
            if (int(entry) == 9 or int(entry) == 10 or int(entry) == 13) or (32 <= int(entry) <= 126):
                stripped_message += chr(int(entry))

    elif type(content_data) == str:

        for entry in content_data:
            if (ord(entry) == 9 or ord(entry) == 10 or ord(entry) == 13) or (32 <= ord(entry) <= 126):
                stripped_message += entry

    return stripped_message.replace("\x00", "")


#######################
# Profiling Functions #
#######################


def score_behaviours(behaviour_tags: Dict[str, Any]) -> Tuple[float, str, Dict[str, Any]]:
    """
    Scores the identified behaviours.

    Args:
        behaviour_tags: {"Downloader": {"marks": ["Invoke-WebRequest]}}

    Returns:
        score: 1.0
        verdict: "Likely Benign"
        behaviour_tags: {"Downloader": {"marks": ["Invoke-WebRequest], "score": 3.0}}
    """
    score_values = {

        # Negative
        # Behaviours which are generally only seen in Malware.
        "Code Injection": 3.0,
        "Key Logging": 3.0,
        "Screen Scraping": 2.0,
        "AppLocker Bypass": 1.0,
        "AMSI Bypass": 1.0,
        "Clear Logs": 1.0,
        "Coin Miner": 1.0,
        "Embedded File": 2.0,
        "Abnormal Size": 1.0,
        "Ransomware": 1.0,
        "DNS C2": 1.0,
        "Disabled Protections": 1.0,
        "Negative Context": 1.0,
        SUSPICIOUS_BEHAVIOUR_COMBO: 3.0,
        "Hidden Window": 1.0,
        "Script Execution": 1.0,
        "Uses WMI": 1.0,
        "Starts RunDll": 1.0,

        # Neutral
        # Behaviours which require more context to infer intent.
        "Downloader": 1.0,
        "Starts Process": 1.0,
        "Compression": 1.0,
        "Custom Web Fields": 1.0,
        "Persistence": 1.0,
        "Sleeps": 1.0,
        "Uninstalls Apps": 1.0,
        "Obfuscation": 2.0,
        "Deobfuscation": 1.0,
        "Crypto": 2.0,
        "Enumeration": 1.0,
        "Registry": 1.0,
        "Sends Data": 2.0,
        "Byte Usage": 2.0,
        "SysInternals": 1.0,
        "One Liner": 1.0,
        "Email": 1.0,
        "Ping": 1.0,
        "Mshta": 1.0,
        "Imports BitsTransfer": 1.0,

        # Benign
        # Behaviours which are generally only seen in Benign scripts - subtracts from score.
        "Script Logging": -1.0,
        "License": -1.0,
        "Function Body": -1.0,
        "Positive Context": -1.0,
    }

    score = 0.0

    for behaviour in behaviour_tags.keys():

        if "Obfuscation:" in behaviour:
            obfus, name = behaviour.split(':')
            behaviour_tags[behaviour]["score"] = score_values[obfus]
            behaviour = obfus
        else:
            behaviour_tags[behaviour]["score"] = score_values[behaviour]

        score += score_values[behaviour]

    if score < 0.0:
        score = 0.0

    # These verdicts are arbitrary and can be adjusted as necessary.
    if score == 0 and behaviour_tags == {}:
        verdict = "Unknown"
    elif score < 4:
        verdict = "Low Risk"
    elif 6 > score >= 4:
        verdict = "Mild Risk"
    elif 6 <= score < 10:
        verdict = "Moderate Risk"
    elif 10 <= score <= 20:
        verdict = "Elevated Risk"
    else:
        verdict = "Severe Risk"

    return score, verdict, behaviour_tags


def profile_behaviours(behaviour_tags: Dict[str, any], original_data, alternative_data) -> Dict[str, Any]:
    """
    Identifies the core behaviours for this profiling script. Broken into 3 sections for Malicious, Neutral, Benign.
    Includes meta-behaviours and keyword/combinations.

    Args:
        behaviour_tags: {}
        original_data: Original PowerShell Script
        alternative_data: Normalize/Unraveled PowerShell Script

    Returns:
        behaviour_tags: [{"name": "Downloader", "marks": ["Invoke-WebRequest"]]
    """
    # {Behaviour:[["entry1","entry2"],["entry3","entry4"]]}
    behaviour_col = {}
    obf_type = None

    # Generates possible code injection variations.
    # Create memory
    c1 = ["VirtualAlloc", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", "HeapAlloc", "calloc"]
    # Move to memory
    c2 = ["RtlMoveMemory", "WriteProcessMemory", "memset", "Runtime.InteropServices.Marshal]::Copy",
          "Runtime.InteropServices.Marshal]::WriteByte"]
    # Execute in memory
    c3 = ["CallWindowProcA", "CallWindowProcW", "DialogBoxIndirectParamA", "DialogBoxIndirectParamW",
          "EnumCalendarInfoA", "EnumCalendarInfoW", "EnumDateFormatsA", "EnumDateFormatsW", "EnumDesktopWindows",
          "EnumDesktopsA", "EnumDesktopsW", "EnumLanguageGroupLocalesA", "EnumLanguageGroupLocalesW", "EnumPropsExA",
          "EnumPropsExW", "EnumPwrSchemes", "EnumResourceTypesA", "EnumResourceTypesW", "EnumResourceTypesExA",
          "EnumResourceTypesExW", "EnumSystemCodePagesA", "EnumSystemCodePagesW", "EnumSystemLanguageGroupsA",
          "EnumSystemLanguageGroupsW", "EnumSystemLocalesA", "EnumSystemLocalesW", "EnumThreadWindows",
          "EnumTimeFormatsA", "EnumTimeFormatsW", "EnumUILanguagesA", "EnumUILanguagesW", "EnumWindowStationsA",
          "EnumWindowStationsW", "EnumWindows", "EnumerateLoadedModules", "EnumerateLoadedModulesEx",
          "EnumerateLoadedModulesExW", "GrayStringA", "GrayStringW", "NotifyIpInterfaceChange",
          "NotifyTeredoPortChange", "NotifyUnicastIpAddressChange", "SHCreateThread", "SHCreateThreadWithHandle",
          "SendMessageCallbackA", "SendMessageCallbackW", "SetWinEventHook", "SetWindowsHookExA", "SetWindowsHookExW",
          "CreateThread", "Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer", "DeviceIoControl"]

    behaviour_col["Code Injection"] = [["Read", "Write", "Load", "Reflection.Assembly", "EntryPoint.Invoke"], ]

    behaviour_col["Key Logging"] = [
        ["GetAsyncKeyState"],
        ["Windows.Forms.Keys"],
        ["LShiftKey", "RShiftKey", "LControlKey", "RControlKey"],
        ["GetKeyboardState"],
        ["MapVirtualKey"],
        ["Start-KeyLogger"],
    ]

    behaviour_col["Screen Scraping"] = [
        ["Drawing.Bitmap", "Width", "Height", "Screen"],
        ["Drawing.Graphics", "FromImage", "Screen"],
        ["CopyFromScreen", "Size"],
    ]

    behaviour_col["AppLocker Bypass"] = [
        ["regsvr32", "/i:http", "scrobj.dll"],
    ]

    behaviour_col["AMSI Bypass"] = [
        ["Management.Automation.AMSIUtils", "amsiInitFailed"],
        ["Expect100Continue"],
    ]

    behaviour_col["Clear Logs"] = [
        ["GlobalSession.ClearLog"],
        ["clear-eventlog", "Windows PowerShell"],
        ["clear-eventlog", "Applicatipn"],
        ["clear-eventlog", "System"],
        ["ClearMyTracksByProcess"],
    ]

    behaviour_col["Coin Miner"] = [
        ["miner_path", "miner_url"],
        ["minername", "Miner Path"],
        ["RainbowMiner"],
        ["Get-BestMiners"],
        ["xmrig.exe"],
    ]

    behaviour_col["Embedded File"] = [
        ["MZ", "This program cannot be run in DOS mode"],
        ["TVqQAAMAAAA"],  # B64 MZ Header
    ]

    behaviour_col["Abnormal Size"] = [  # Work done in processing.
    ]

    behaviour_col["Ransomware"] = [
        ["README-Encrypted-Files.html"],
        ["!!! Your Personal identification ID:"],
        ["DECRYPT_INSTRUCTIONS.html"],
        ["BinaryWriter", "Cryptography", "ReadWrite", "Add-Content", "html"],
    ]

    behaviour_col["DNS C2"] = [
        ["nslookup", "querytype=txt", "8.8.8.8"],
    ]

    behaviour_col["Disabled Protections"] = [
        ["REG_DWORD", "DisableAntiSpyware"],
        ["REG_DWORD", "DisableAntiVirus"],
        ["REG_DWORD", "DisableScanOnRealtimeEnable"],
        ["REG_DWORD", "DisableBlockAtFirstSeen"],
        ["Uninstall-WindowsFeature", "Windows-Defender"],
        ["Set-MpPreference", "-DisableRealtimeMonitoring", "$true"],
    ]

    behaviour_col["Negative Context"] = [
        ["Invoke-Shellcode"],  # Could be PowerSploit, Empire, or other frameworks.
        ["meterpreter"],
        ["metasploit"],
        ["HackerTools"],
        ["eval(function(p,a,c,k,e,d)"],  # Moved from obfuscation - unable to find benign usage.
        ["Download_Execute"],
        ["exetotext"],
        ["PostExploit"],
        ["PEBytes32", "PEBytes64"],  # Could be Mimikatz or Empire.
        ["Invoke-Mypass"],
        ["PowerShell", "bypass", "hidden", "WebClient", "DownloadFile", "exe", "Start-Process", "APPDATA"],
        ["certutil.exe", "BEGIN CERTIFICATE"],  # "function set-Certificate()
        ["Invoke-BloodHound"], ["keylogging"],
        ["Auto-attack"],
        ["pastebin.com/raw/"],  # Common script downloading location.
        ["Shellcode", "payload"],
        ["$forward_port", "$forward_path", "$MyInvocation.MyCommand.Path", "${global:", "-Namespace Kernel32"],
        ["CurrentDomain.GetAssemblies()", "GetProcAddress').Invoke", "SetImplementationFlags"],
        ["return $Win32Types", "return $Win32Constants"],
        ["Get-Random -count 16", "Win32_NetworkAdapterConfiguration", "whoami", "POST"],
        ["Get-Random -Minimum", "System.Buffer]::BlockCopy", "GetResponseStream()", "POST"],
        ["*.vbs", "*.lnk", "DllOpen", "DllCall"],
        ["start-process  -WindowStyle hidden -FilePath taskkill.exe -ArgumentList"],
        ["$xorkey", "xordData"],
        ["powershell_payloads"],
        ["attackcode"],
        ["namespace PingCastle"],
        ["br.bat", "Breach.exe", "syspull.ps1"],
        # ["Bruteforce", "password"],
        # ["Brute-force", "password"],
        ["exploit", "vulnerbility", "cve-"],
        ["Privilege Escalation"],
        ["Net.WebClient", "DownloadString", "IEX", "New-Object"],
        ["-W", "Hidden", "-Exec", "Bypass"],
        ["taskkill", "/im", "/f"],
        ["net", "stop", "/y"],
        ["sc", "config", "start=", "disabled"],
        # Names of researchers / script authors for common offensive scripts that frequently show up in copied code.
        # Low hanging fruit - not necessarily always bad but increase risk.
        ["khr0x40sh"],
        ["harmj0y"],
        ["mattifestation"],
        ["FuzzySec"],
    ]

    behaviour_col["Downloader"] = [
        ["Net.WebClient"],
        ["DownloadFile"],
        ["DownloadString"],
        ["DownloadData"],
        ["WebProxy", "Net.CredentialCache"],
        ["Start-BitsTransfer"],
        ["bitsadmin"],
        ["Sockets.TCPClient", "GetStream"],
        ["$env:LocalAppData"],
        ["Invoke-WebRequest"],
        ["Net.WebRequest"],
        ["wget"],
        # ["Get-Content"],
        ["send", "open", "responseBody"],
        ["HttpWebRequest", "GetResponse"],
        ["InternetExplorer.Application", "Navigate"],
        ["Excel.Workbooks.Open('http"],
        ["Notepad", "SendKeys", "ForEach-Object", "Clipboard", "http"],
        ["Excel.Workbooks.Open", "http", "ReleaseComObject", "Sheets", "Item", "Range", "Row"],
        ["iwr", "-outf"],
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7.3
        [". ", "mshta.exe", "http"]
    ]

    behaviour_col["Starts Process"] = [
        ["Start-Process"],
        ["New-Object", "IO.MemoryStream", "IO.StreamReader"],
        ["Diagnostics.Process]::Start"],
        ["RedirectStandardInput", "UseShellExecute"],
        ["Invoke-Item"],
        ["WScript.Shell", "ActiveXObject", "run"],
        ["START", "$ENV:APPDATA", "exe", "http"],
        ["START", "rundll32"],
    ]

    behaviour_col["Starts RunDll"] = [
         ["START", "rundll32"]
    ]

    behaviour_col["Script Execution"] = [
        ["Invoke-Expression"],
        ["Invoke-Command"],
        ["InvokeCommand"],
        ["Invoke-Script"],
        ["InvokeScript"],
        [".Invoke("],
        ["IEX("],
        ["|IEX"],
        ["wScript.Run"],
        ["wscript.shell"],
        ["ActiveXObject", "ShellExecute"],
        ["$ExecutionContext|Get-Member)[6].Name"],  # Invoke-Command
        ["shellexecute"],
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-7.3
        [". ", ".exe"],
    ]

    behaviour_col["Compression"] = [
        ["Convert", "FromBase64String", "Text.Encoding"],
        ["IO.Compression.GzipStream"],
        ["Compression.CompressionMode]::Decompress"],
        ["IO.Compression.DeflateStream"],
        ["IO.MemoryStream"],
    ]

    behaviour_col["Hidden Window"] = [
        ["WindowStyle", "Hidden"],
        ["CreateNoWindow=$true"],
        ["Window.ReSizeTo 0, 0"],
        ["-W", "Hidden"],
    ]

    behaviour_col["Custom Web Fields"] = [
        ["Headers.Add"],
        ["SessionKey", "SessiodID"],
        ["Method", "ContentType", "UserAgent", "WebRequest]::create"],
    ]

    behaviour_col["Persistence"] = [
        ["New-Object", "-COMObject", "Schedule.Service"],
        ["SCHTASKS"],
    ]

    behaviour_col["Sleeps"] = [
        ["Start-Sleep"],
        ["sleep -s"],
    ]

    behaviour_col["Uninstalls Apps"] = [
        ["foreach", "UninstallString"],
        ["start", "wmic", "product", "call", "uninstall", "/nointeractive"],
        ["Uninstall-WindowsFeature"],
    ]

    behaviour_col["Obfuscation"] = [
        ["-Join", "[int]", "-as", "[char]"],
        ["-bxor"],
        ["PtrToStringAnsi"],
        ["[-1..-"],
        ["[array]::Reverse"],
        ["$ENV:COMSPEC\\..\\"],
    ]

    behaviour_col["Deobfuscation"] = [
        ["[Convert]::FromBase64String("],
        ["[System.Convert]::FromBase64String("],
    ]

    behaviour_col["Crypto"] = [
        ["Security.Cryptography.AESCryptoServiceProvider", "Mode", "Key", "IV"],
        ["CreateEncryptor().TransformFinalBlock"],
        ["CreateDecryptor().TransformFinalBlock"],
        ["Security.Cryptography.CryptoStream"],
        ["CreateAesManagedObject", "Mode", "Padding"],
        ["ConvertTo-SecureString", "-Key"],
    ]

    behaviour_col["Enumeration"] = [
        ["Environment]::UserDomainName"],
        ["Environment]::UserName"],
        ["$env:username"],
        ["Environment]::MachineName"],
        ["Environment]::GetFolderPath"],
        ["IO.Path]::GetTempPath"],
        ["$env:windir"],
        ["Win32_NetworkAdapterConfiguration"],
        ["Win32_OperatingSystem"],
        ["Win32_ComputerSystem"],
        ["Principal.WindowsIdentity]::GetCurrent"],
        ["Principal.WindowsBuiltInRole]", "Administrator"],
        ["Diagnostics.Process]::GetCurrentProcess"],
        ["PSVersionTable.PSVersion"],
        ["Diagnostics.ProcessStartInfo"],
        ["Win32_ComputerSystemProduct"],
        ["Get-Process -id"],
        ["$env:userprofile"],
        ["Forms.SystemInformation]::VirtualScreen"],
        ["ipconfig"],
        ["Win32_Processor", "AddressWidth"],
        ["GetHostAddresses"],
        ["IPAddressToString"],
        ["Get-Date"],
        ["HNetCfg.FwPolicy"],
        ["GetTokenInformation"],
    ]

    behaviour_col["Registry"] = [
        ["HKCU:\\"],
        ["HKLM:\\"],
        ["New-ItemProperty", "-Path", "-Name", "-PropertyType", "-Value"],
        ["reg add"],
        ["reg delete"],
        ["reg.exe add"],
        ["reg.exe delete"],
    ]

    behaviour_col["Sends Data"] = [
        ["UploadData", "POST"],
    ]

    behaviour_col["Byte Usage"] = [  # Additional checks done in processing.
        ["AppDomain]::CurrentDomain.GetAssemblies()", "GlobalAssemblyCache"],
        ["[Byte[]] $buf"],
        ["IO.File", "WriteAllBytes"],
    ]

    behaviour_col["SysInternals"] = [
        ["procdump", "sysinternals"],
        ["psexec", "sysinternals"],
    ]

    behaviour_col["One Liner"] = [  # Work done in processing.
    ]

    behaviour_col["Script Logging"] = [
        ["LogMsg", "LogErr"],
        ["Write-Debug"],
        ["Write-Log"],
        ["Write-Host"],
        ["Exception.Message"],
        ["Write-Output"],
        ["Write-Warning"],
    ]

    behaviour_col["License"] = [
        ["# Copyright", "# Licensed under the"],
        ["Copyright (C)"],
        ["Permission is hereby granted"],
        ['THE SOFTWARE IS PROVIDED "AS IS"'],
        ["Begin signature block"]
    ]

    behaviour_col["Function Body"] = [
        [".SYNOPSIS", ".DESCRIPTION", ".EXAMPLE"],
        [".VERSION", ".AUTHOR", ".CREDITS"],
    ]

    behaviour_col["Positive Context"] = [
        ["createButton"],
        ["toolTip"],
        ["deferral"],
        ["Start-AutoLab"],
        ["Failed to download"],
        ["FORENSICS SNAPSHOT"],
        ["choclatey"],
        ["Chocolatey"],
        ["chef-client", "chef.msi"],
        ["Node.js", "nodejs.org"],
        ["sqlavengers"],
        ["SpyAdBlocker.lnk"],
        ["ReadMe.md"],
        ["Remote Forensic Snapshot"],
        ["Function Write-Log"],
        ["Remote Forensic Snapshot"],
    ]

    behaviour_col["Email"] = [
        ["SMTP"],
        ["send-mailmessage"],
        ["-smtpServer"],
    ]

    behaviour_col["Uses WMI"] = [
        ["wmic"],
        ["gwmi"],
        ["Get-WmiObject"],
    ]

    behaviour_col["Ping"] = [
        ["Test-Connection"]
    ]

    behaviour_col["Mshta"] = [
        ["mshta.exe"]
    ]

    behaviour_col["Imports BitsTransfer"] = [
        ["Import-Module", "BitsTransfer"]
    ]

    # Behavioural Combos combine a base grouping of behaviours to help raise the score of files without a lot of complexity.
    # Take care in adding to this list and use a minimum length of 3 behaviours (or 2 really good ones!).
    # Instances where FP hits occur have been commented out

    behaviour_combos = [
        ["Downloader", "One Liner"],
        ["Downloader", "Script Execution", "Crypto", "Enumeration"],
        ["Downloader", "Script Execution", "Persistence", "Enumeration"],
        ["Downloader", "Script Execution", "Starts Process", "Enumeration"],
        ["Script Execution", "One Liner"],
        # ["Script Execution", "Starts Process", "Downloader"],
        ['Script Execution', 'Starts Process', 'Downloader', 'One Liner'],
        ['Script Execution', 'Downloader', 'Custom Web Fields'],
        # ['Script Execution', 'Downloader', 'One Liner'],
        ["Script Execution", "Hidden Window", "Downloader"],
        ['Script Execution', 'Crypto', 'Obfuscation'],
        # ['Starts Process', 'Downloader', 'Custom Web Fields'],
        # ['Starts Process', 'Downloader', 'One Liner'],
        # ["Starts Process", "Downloader", "Enumeration", "One Liner"],
        ["Hidden Window", "Persistence", "Downloader"],
        ["Downloader", "Starts Process", "Sleeps"],
        ["Downloader", "Starts Process", "Hidden Window"],
        ["Downloader", "Starts RunDll"],
        ["Downloader", "Script Execution", "Ping"],
        ["Script Execution", "Ping"],
        ["Downloader", "Script Execution", "Mshta"],
        ["Downloader", "Imports BitsTransfer", "Deobfuscation", "Compression", "Sleeps"],
    ]

    for behaviour, checks in behaviour_col.items():
        # Check Behaviour Keyword/Combinations.
        for check in checks:
            bh_flag = True
            for value in check:
                if value.lower() not in alternative_data.lower():
                    bh_flag = None
                    break

            if bh_flag:
                if behaviour not in behaviour_tags:
                    behaviour_tags[behaviour] = {"marks": [item for item in check]}
                else:
                    behaviour_tags[behaviour]["marks"].extend(check)

        # Separate Meta-behavioural Checks.
        if behaviour == "Obfuscation":

            obf_type = None

            # Character Frequency Analysis (Original Script only).
            if (original_data.count("w") >= 500 or
                    original_data.count("4") >= 250 or
                    original_data.count("_") >= 250 or
                    original_data.count("D") >= 250 or
                    original_data.count("C") >= 200 or
                    original_data.count("K") >= 200 or
                    original_data.count("O") >= 200 or
                    original_data.count(":") >= 100 or
                    original_data.count(";") >= 100 or
                    original_data.count(",") >= 100 or
                    (original_data.count("(") >= 50 and original_data.count(")") >= 50) or
                    (original_data.count("[") >= 50 and original_data.count("]") >= 50) or
                (original_data.count("{") >= 50 and original_data.count("}") >= 50)
                    # Added a line count length to try and stop this triggering on long benigns.
                ) and len(re.findall(r"(\n|\r\n)", original_data.strip())) <= 50:

                if behaviour not in behaviour_tags:
                    behaviour_tags[behaviour] = {"marks": []}
                    obf_type = "Char Frequency"

            # Check Symbol Usage.
            if len(re.findall(r"\\_+/", alternative_data)) >= 50:

                if behaviour not in behaviour_tags:
                    behaviour_tags[behaviour] = {"marks": []}
                    obf_type = "High Symbol"

            # Check unique high variable declaration (includes JavaScript).
            if len(list(set(re.findall(r"var [^ ]+ ?=", alternative_data)))) >= 40 or \
                    len(list(set(re.findall(r"\\$\w+?(?:\s*)=", alternative_data)))) >= 40:

                if behaviour not in behaviour_tags:
                    behaviour_tags[behaviour] = {"marks": []}
                    obf_type = "High Variable"

        elif behaviour == "Byte Usage":

            if len(re.findall(r"0x[A-F0-9a-f][A-F0-9a-f],", alternative_data)) >= 100:
                if behaviour not in behaviour_tags:
                    behaviour_tags[behaviour] = {"marks": []}

        elif behaviour == "One Liner":

            if len(re.findall(r"(\n|\r\n)", original_data.strip())) == 0:
                if behaviour not in behaviour_tags:
                    behaviour_tags[behaviour] = {"marks": []}

        elif behaviour == "Abnormal Size":

            if len(original_data) >= 1000000 or len(re.findall(r"(\n|\r\n)", original_data)) >= 5000:
                if behaviour not in behaviour_tags:
                    behaviour_tags[behaviour] = {"marks": []}

        elif behaviour == "Code Injection":
            cf1, cf2, cf3 = None, None, None
            for entry in c1:
                if entry.lower() in alternative_data.lower() and not cf1:
                    cf1 = entry
            for entry in c2:
                if entry.lower() in alternative_data.lower() and not cf2 and cf1:
                    cf2 = entry
            for entry in c3:
                if entry.lower() in alternative_data.lower() and not cf3 and cf1 and cf2:
                    cf3 = entry
            if cf1 and cf2 and cf3:
                if behaviour not in behaviour_tags:
                    behaviour_tags[behaviour] = {"marks": [cf1, cf2, cf3]}

        elif behaviour == "Mshta":
            # Mshta Downloader
            mshta_search = re.search(r"c:\\\\windows\\\\system32\\\\mshta\.exe\s+[\'\"](https?:\/\/.+[\'\"])", original_data, re.IGNORECASE)
            if mshta_search:
                behaviour_tags["Mshta"]["marks"].append(mshta_search.group(1))

    # Tries to catch download cradle PowerShell scripts where the obfuscation isn't identified.
    # Examples are heavy variable command usage for chaining/parsing.
    if len(behaviour_tags.keys()) == 2 and "One Liner" in behaviour_tags and (
            "http://" in alternative_data.lower() or "https://" in alternative_data.lower()) and \
            ("Script Execution" in behaviour_tags or "Starts Process" in behaviour_tags
             ):
        behaviour_tags["Downloader"] = {"marks": []}
        behaviour_tags["Obfuscation"] = {"marks": []}
        obf_type = "Hidden Commands"

    # Applies identified Obfuscation Type to behaviour.
    if obf_type:
        behaviour_tags[f"Obfuscation:{obf_type}"] = behaviour_tags["Obfuscation"]
        del behaviour_tags["Obfuscation"]

    # Tries to determine if any behaviour combos exist - should always be last step.
    for combo_row in behaviour_combos:
        found_flag = 1
        for behaviour in combo_row:
            if behaviour not in behaviour_tags:
                found_flag = 0
        if found_flag == 1:
            if SUSPICIOUS_BEHAVIOUR_COMBO not in behaviour_tags:
                behaviour_tags[SUSPICIOUS_BEHAVIOUR_COMBO] = {"marks": []}
            for item in combo_row:
                if item not in behaviour_tags[SUSPICIOUS_BEHAVIOUR_COMBO]["marks"]:
                    behaviour_tags[SUSPICIOUS_BEHAVIOUR_COMBO]["marks"].append(item)

    return behaviour_tags


def family_finder(content_data: str) -> Dict[str, Dict[str, List]]:
    """
    Attempts to profile a Malware Family (typically PowerShell Attack Frameworks) via keywords or REGEX.
    In general, preference is to match against all lowercase strings, this way CaMeL CaSe is ignored.

    Args:
        content_data: Normalize/Unraveled PowerShell Script

    Returns:
        families: ["PowerSploit"]
    """
    families: Dict[str, Dict[str, List]] = defaultdict(defaultdict(list).copy)

    # Family: Magic Unicorn
    # Reference: https://github.com/trustedsec/unicorn
    if re.search(r"\$w = Add-Type -memberDefinition \$[a-zA-Z0-9]{3,4} -Name", content_data):
        families["Magic Unicorn"][REGEX_INDICATORS].append("\$w = Add-Type -memberDefinition \$[a-zA-Z0-9]{3,4} -Name")

    if (all(entry in content_data.lower() for entry in ["sv", "gv", "value.tostring"]) and
            re.search(r"[a-zA-Z0-9+/=]{250,}", content_data)):
        families["Magic Unicorn"][REGEX_INDICATORS].append("[a-zA-Z0-9+/=]{250,}")
        families["Magic Unicorn"][STR_INDICATORS].extend(["sv", "gv", "value.tostring"])

    if re.search(r"\$[a-zA-Z0-9]{5,7} = \'\[DllImport.+Start-sleep 60};", content_data):
        families["Magic Unicorn Modified"][REGEX_INDICATORS].append(
            "\$[a-zA-Z0-9]{5,7} = \'\[DllImport.+Start-sleep 60};")

    # Family: Shellcode Injector (variant of Unicorn prior to randomization)
    # Reference: N/A
    if re.search(r"(\$c = |\$1 = [\"\']\$c = )", content_data) and \
            all(entry in content_data.lower() for entry in ["$g = 0x1000", "$z.length -gt 0x1000", "$z[$i]"]):
        families["Shellcode Injector"][REGEX_INDICATORS].append("(\$c = |\$1 = [\"\']\$c = )")
        families["Shellcode Injector"][STR_INDICATORS].extend(["$g = 0x1000", "$z.length -gt 0x1000", "$z[$i]"])

    # Family: ICMP Shell
    # Reference: https://github.com/inquisb/icmpsh
    if all(
            entry in content_data.lower()
            for entry in ["buffer", "getstring", "getbytes", "networkinformation.ping", "dontfragment"]):
        families["ICMP Shell"][STR_INDICATORS].extend(
            ["buffer", "getstring", "getbytes", "networkinformation.ping", "dontfragment"])

    if all(entry in content_data.lower() for entry in ["icmpsh", "nishang"]):
        families["ICMP Shell"][STR_INDICATORS].extend(["icmpsh", "nishang"])

    if "invoke-powershellicmp" in content_data.lower():
        families["ICMP Shell"][STR_INDICATORS].append("invoke-powershellicmp")

    # Family: Social Engineering Toolkit (SET)
    # Reference: https://github.com/trustedsec/social-engineer-toolkit
    if re.search(r"\$code = [\']{1,2}\[DllImport", content_data):
        families["SET"][REGEX_INDICATORS].append("\$code = [\']{1,2}\[DllImport")

    if any(entry in content_data.lower() for entry in ["$sc.length -gt 0x1000)", "$winfunc::memset"]):
        families["SET"][STR_INDICATORS].extend(["$sc.length -gt 0x1000)", "$winfunc::memset"])

    # Family: PowerDump
    # Reference: https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/powershell/powerdump.powershell
    if all(entry in content_data.lower() for entry in ["function loadapi", "$code = @"]):
        families["PowerDump"][STR_INDICATORS].extend(["function loadapi", "$code = @"])

    if "invoke-powerdump" in content_data.lower():
        families["PowerDump"][STR_INDICATORS].append("invoke-powerdump")

    # Family: BashBunny
    # Reference: https://github.com/hak5/bashbunny-payloads/blob/master/payloads/library/Incident_Response/Hidden_Images/run.ps1
    if any(entry in content_data.lower() for entry in ["bashbunny", "loot\hidden-image-files"]):
        families["BashBunny"][STR_INDICATORS].extend(["bashbunny", "loot\hidden-image-files"])

    # Family: Veil
    # Reference: https://github.com/yanser237/https-github.com-Veil-Framework-Veil-Evasion/blob/master/modules/payloads/powershell/shellcode_inject/virtual.py
    if any(entry in content_data.lower() for entry in ["0x1000,0x3000,0x40", "start-sleep -second 100000"]):
        families["Veil Embed"][STR_INDICATORS].extend(["0x1000,0x3000,0x40", "start-sleep -second 100000"])

    if all(entry in content_data.lower() for entry in [
        "invoke-expression $(new-object io.streamreader ($(new-object io.compression.deflatestream",
            ")))), [io.compression.compressionmode]::decompress)), [text.encoding]::ascii)).readtoend();"]):
        families["Veil Stream"][STR_INDICATORS].extend([
            "invoke-expression $(new-object io.streamreader ($(new-object io.compression.deflatestream",
            ")))), [io.compression.compressionmode]::decompress)), [text.encoding]::ascii)).readtoend();"])

    # Family: PowerWorm
    # Reference: https://github.com/mattifestation/PowerWorm/blob/master/PowerWorm_Part_5.ps1
    if all(entry in content_data.lower() for entry in ["bootstrapped 100%", ".onion/get.php?s=setup"]):
        families["PowerWorm"][STR_INDICATORS].extend(["bootstrapped 100%", ".onion/get.php?s=setup"])

    # Family: PowerShell Empire
    # Reference: https://github.com/EmpireProject/Empire/blob/293f06437520f4747e82e4486938b1a9074d3d51/lib/common/stagers.py#L344
    # Reference: https://github.com/EmpireProject/Empire/blob/master/lib/listeners/http_com.py
    # Reference: https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/registry.py
    # Reference: https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py
    # Reference: https://github.com/EmpireProject/Empire/blob/master/lib/listeners/http_hop.py

    if any(entry in content_data.lower() for entry in [
        "|%{$_-bxor$k[$i++%$k.length]};iex",
        "$wc=new-object system.net.webclient;$u='mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0) like gecko';$wc.headers.add('user-agent',$u);$wc.proxy = [system.net.webrequest]::defaultwebproxy;$wc.proxy.credentials = [system.net.credentialcache]::defaultnetworkcredentials;",
        "{$gps['scriptblockLogging']['enablescriptblocklogging']=0;$gps['scriptblockLogging']['enablescriptblockinvocationlogging']=0}else{[scriptblock]",
        "$r={$d,$k=$args;$S=0..255;0..255|%{$J=($j+$s[$_]",
        "$iv=$data[0..3];$data=$data[4..$data.length];-join[char[]](& $r $data ($iv+$k)",
        "invoke-winenum",
        "invoke-postexfil",
        "invoke-empire",
            "get-posthashdumpscript"]):
        families["PowerShell Empire"][STR_INDICATORS].extend([
            "|%{$_-bxor$k[$i++%$k.length]};iex",
            "$wc=new-object system.net.webclient;$u='mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0) like gecko';$wc.headers.add('user-agent',$u);$wc.proxy = [system.net.webrequest]::defaultwebproxy;$wc.proxy.credentials = [system.net.credentialcache]::defaultnetworkcredentials;",
            "{$gps['scriptblockLogging']['enablescriptblocklogging']=0;$gps['scriptblockLogging']['enablescriptblockinvocationlogging']=0}else{[scriptblock]",
            "$r={$d,$k=$args;$S=0..255;0..255|%{$J=($j+$s[$_]",
            "$iv=$data[0..3];$data=$data[4..$data.length];-join[char[]](& $r $data ($iv+$k)",
            "invoke-winenum",
            "invoke-postexfil",
            "invoke-empire",
            "get-posthashdumpscript"])

    if all(entry in content_data.lower() for entry in [
            "schtasks.exe",
            'powershell.exe -noni -w hidden -c "iex ([text.encoding]::unicode.getstring([convert]::frombase64string']):
        families["PowerShell Empire"][STR_INDICATORS].extend([
            "schtasks.exe",
            'powershell.exe -noni -w hidden -c "iex ([text.encoding]::unicode.getstring([convert]::frombase64string'])

    if re.search(r"\$RegPath = .+\$parts = \$RegPath\.split.+\$path = \$RegPath\.split", content_data, re.IGNORECASE):
        families["PowerShell Empire"][REGEX_INDICATORS].append(
            "\$RegPath = .+\$parts = \$RegPath\.split.+\$path = \$RegPath\.split")

    if all(entry in content_data.lower() for entry in ["shellcode1", "shellcode2", "getcommandlineaaddr"]):
        families["PowerShell Empire"][STR_INDICATORS].extend(["shellcode1", "shellcode2", "getcommandlineaaddr"])

    if all(entry in content_data.lower() for entry in ["empireip", "empireport", "empirekey"]):
        families["PowerShell Empire"][STR_INDICATORS].extend(["empireip", "empireport", "empirekey"])

    # Family: Powerfun
    # Reference: https://github.com/rapid7/metasploit-framework/blob/cac890a797d0d770260074dfe703eb5cfb63bd46/data/exploits/powershell/powerfun.ps1
    # Reference: https://github.com/rapid7/metasploit-framework/pull/5194
    if all(entry in content_data.lower()
           for entry in ["new-object system.net.sockets.tcpclient", "$sendback2 = $sendback"]):
        families["Powerfun Bind"][STR_INDICATORS].extend(
            ["new-object system.net.sockets.tcpclient", "$sendback2 = $sendback"])

    if re.search(r"\$s=New-Object IO\.MemoryStream\(,\[Convert]::FromBase64String\([\'\"]{1,2}H4sIA[a-zA-Z0-9+/=]+"
                 r"[\'\"]{1,2}\)\);IEX \(New-Object IO\.StreamReader\(New-Object IO\.Compression\.GzipStream"
                 r"\(\$s,\[IO\.Compression\.CompressionMode]::Decompress\)\)\)\.ReadToEnd\(\)",
                 content_data, re.IGNORECASE):
        families["Powerfun Reverse"][REGEX_INDICATORS].append(
            "\$s=New-Object IO\.MemoryStream\(,\[Convert]::FromBase64String\([\'\"]{1,2}H4sIA[a-zA-Z0-9+/=]+[\'\"]{1,2}\)\);IEX \(New-Object IO\.StreamReader\(New-Object IO\.Compression\.GzipStream\(\$s,\[IO\.Compression\.CompressionMode]::Decompress\)\)\)\.ReadToEnd\(\)")

    # Family: Mimikatz
    # Reference: https://github.com/gentilkiwi/mimikatz
    if all(entry in content_data.lower() for entry in ["dumpcred", "dumpcert", "customcommand"]):
        families["Mimikatz"][STR_INDICATORS].extend(["dumpcred", "dumpcert", "customcommand"])

    if all(entry in content_data.lower() for entry in
           ["virtualprotect.invoke", "memcpy.invoke", "getcommandlineaaddr"]):
        families["Mimikatz"][STR_INDICATORS].extend(["virtualprotect.invoke", "memcpy.invoke", "getcommandlineaaddr"])

    if all(
            entry in content_data.lower()
            for entry in ["[parameter(parametersetname = ", ", position = 1)]", "[switch]", "autolayout", "ansiclass"]):
        families["Mimikatz"][STR_INDICATORS].extend(["[parameter(parametersetname = ", ", position = 1)]",
                                                     "[switch]", "autolayout", "ansiclass"])

    if any(entry in content_data.lower() for entry in ["invoke-mimikatz", "$thisisnotthestringyouarelookingfor"]):
        families["Mimikatz"][STR_INDICATORS].extend(["invoke-mimikatz", "$thisisnotthestringyouarelookingfor"])

    # Family: Mimikittenz
    # Reference: https://github.com/putterpanda/mimikittenz/
    if any(entry in content_data.lower() for entry in ["inspectproc", "readprocessmemory", "mimikittenz"]):
        families["Mimikittenz"][STR_INDICATORS].extend(["inspectproc", "readprocessmemory", "mimikittenz"])

    # Family: PowerSploit
    # Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-TimedScreenshot.ps1
    # Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
    if all(
            entry in content_data.lower() for entry in ["function get-timedscreenshot", "#load required assembly"]):
        families["PowerSploit"][STR_INDICATORS].extend(["function get-timedscreenshot", "#load required assembly"])

    if any(
            entry in content_data.lower()
            for entry in ["invoke-reflectivepeinjection", "powersploit", "invoke-privesc", "invoke-dllinjection"]):
        families["PowerSploit"][STR_INDICATORS].extend(
            ["invoke-reflectivepeinjection", "powersploit", "invoke-privesc", "invoke-dllinjection"])

    if any(
        entry in content_data.lower()
        for entry
        in
        ["powerview", "invoke-userhunter", "invoke-stealthuserhunter", "invoke-processhunter",
         "invoke-usereventhunter"]):
        families["PowerSploit"][STR_INDICATORS].extend(
            ["powerview", "invoke-userhunter", "invoke-stealthuserhunter", "invoke-processhunter", "invoke-usereventhunter"])

    # Family: DynAmite Launcher (DynAmite Keylogger function is an old version of PowerSploit Get-Keystrokes)
    # Reference: https://webcache.googleusercontent.com/search?q=cache:yKX6QDiuHHMJ:https://leakforums.net/thread-712268+&cd=3&hl=en&ct=clnk&gl=us
    # Reference: https://github.com/PowerShellMafia/PowerSploit/commit/717950d00c7cc352efe8b05c3db84d0e6250474c#diff-8a834e13c96d5508df5ee11bc92c82dd
    if any(entry in content_data.lower() for entry in ['schtasks.exe /create /tn "microsoft\\windows\\dynamite']):
        families["DynAmite Launcher"][STR_INDICATORS].extend(['schtasks.exe /create /tn "microsoft\\windows\\dynamite'])

    if any(entry in content_data.lower() for entry in ["function dynakey"]):
        families["DynAmite KeyLogger"][STR_INDICATORS].extend(["function dynakey"])

    # Family: Invoke-Obfuscation
    # Reference: https://github.com/danielbohannon/Invoke-Obfuscation/blob/master/Out-ObfuscatedStringCommand.ps1
    if all(entry in content_data.lower() for entry in ["shellid[1]", "shellid[13]"]):
        families["Invoke-Obfuscation"][STR_INDICATORS].extend(["shellid[1]", "shellid[13]"])

    # Family: TXT C2
    # Reference: N/A
    if re.search(r"if\([\"\']{2}\+\(nslookup -q=txt", content_data) and \
            re.search(r"\) -match [\"\']{1}@\(\.\*\)@[\"\']{1}\){iex \$matches\[1]}", content_data):
        families["TXT C2"][REGEX_INDICATORS].append("if\([\"\']{2}\+\(nslookup -q=txt")
        families["TXT C2"][REGEX_INDICATORS].append("\) -match [\"\']{1}@\(\.\*\)@[\"\']{1}\){iex \$matches\[1]}")

    # Family: Remote DLL
    # Reference: N/A
    if any(entry in content_data.lower() for entry in ["regsvr32 /u /s /i:http"]):
        families["Remote DLL"][STR_INDICATORS].extend(["regsvr32 /u /s /i:http"])

    # Family: Cobalt Strike
    # Reference: https://www.cobaltstrike.com/
    if any(
            entry in content_data.lower() for entry in ["$doit = @"]):
        families["Cobalt Strike"][STR_INDICATORS].extend(["$doit = @"])

    if all(
            entry in content_data.lower()
            for entry in ["func_get_proc_address", "func_get_delegate_type", "getdelegateforfunctionpointer", "start-job"]):
        families["Cobalt Strike"][STR_INDICATORS].extend(["func_get_proc_address", "func_get_delegate_type",
                                                          "getdelegateforfunctionpointer", "start-job"])

    # Family: vdw0rm
    # Reference: N/A
    if any(entry in content_data.lower() for entry in ["vdw0rm", "*-]nk[-*"]):
        families["vdw0rm"][STR_INDICATORS].extend(["vdw0rm", "*-]nk[-*"])

    # Family: Emotet
    # Reference: N/A
    if all(entry in content_data.lower() for entry in ["invoke-item", "get-item", "length -ge 40000", "break"]):
        families["Emotet"][STR_INDICATORS].extend(["invoke-item", "get-item", "length -ge 40000", "break"])

    # Family: mateMiner 2.0
    # Reference: http://wolvez.club/2018/11/10/mateMinerKiller/
    if all(entry in content_data.lower() for entry in ["killbot", "mimi", "sc"]):
        families["mateMiner"][STR_INDICATORS].extend(["killbot", "mimi", "sc"])

    # Family: DownAndExec
    # Reference: https://www.welivesecurity.com/2017/09/13/downandexec-banking-malware-cdns-brazil/
    if all(entry in content_data.lower() for entry in ["downandexec", "cdn", "set cms="]):
        families["DownAndExec"][STR_INDICATORS].extend(["downandexec", "cdn", "set cms="])

    # Family: Buckeye / Filensfer
    # Reference: https://www.kernelmode.info/forum/viewtopic.php?t=5533
    if all(entry in content_data.lower() for entry in ["error, byebye!", "string re_info", "sockargs"]):
        families["Buckeye"][STR_INDICATORS].extend(["error, byebye!", "string re_info", "sockargs"])

    # Family: APT34
    # Reference: https://www.jishuwen.com/d/2K6t
    if any(entry in content_data.lower() for entry in ["global:$cca", "$ffa = $eea", "$ssa = $qqa"]):
        families["APT34"][STR_INDICATORS].extend(["global:$cca", "$ffa = $eea", "$ssa = $qqa"])

    # Family: MuddyWater
    # Reference: https://blog.talosintelligence.com/2019/05/recent-muddywater-associated-blackwater.html
    if all(entry in content_data.lower() for entry in ["clientfrontLine", "helloserver", "getcommand"]):
        families["MuddyWater"][STR_INDICATORS].extend(["clientfrontLine", "helloserver", "getcommand"])

    if all(
            entry in content_data.lower() for entry in ["projectcode", "projectfirsthit", "getcmdresult"]):
        families["MuddyWater"][STR_INDICATORS].extend(["projectcode", "projectfirsthit", "getcmdresult"])

    if all(
            entry in content_data.lower()
            for entry in ["basicinfocollector", "getclientidentity", "executecommandandsetcommandresultrequest"]):
        families["MuddyWater"][STR_INDICATORS].extend(
            ["basicinfocollector", "getclientidentity", "executecommandandsetcommandresultrequest"])

    # Family: Tennc Webshell
    # Reference: https://github.com/tennc/webshell
    if all(entry in content_data.lower() for entry in ['getparameter("z0")', 'import="java.io.*']):
        families["Tennc Webshell"][STR_INDICATORS].extend(['getparameter("z0")', 'import="java.io.*'])

    # Family: PoshC2
    # Reference: https://github.com/nettitude/PoshC2
    if all(
            entry in content_data.lower()
            for entry in ["function get-key", "importdll", "check for keys not mapped by virtual keyboard"]):
        families["PoshC2"][STR_INDICATORS].extend(
            ["function get-key", "importdll", "check for keys not mapped by virtual keyboard"])

    if any(entry in content_data.lower() for entry in ["poshc2", "powershellc2"]):
        families["PoshC2"][STR_INDICATORS].extend(["poshc2", "powershellc2"])

    # Family: Posh-SecMod
    # Reference: https://github.com/darkoperator/Posh-SecMod
    if any(entry in content_data.lower() for entry in ["posh-secmod"]):
        families["Posh-SecMod"][STR_INDICATORS].extend(["posh-secmod"])

    # Family: Invoke-TheHash
    # Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
    if any(
            entry in content_data.lower()
            for entry in ["new-packetsmb2findrequestfile", "packet_smb2b_header", "new-packetntlmssp"]):
        families["Invoke-TheHash"][STR_INDICATORS].extend(
            ["new-packetsmb2findrequestfile", "packet_smb2b_header", "new-packetntlmssp"])

    # Family: Nishang
    # Reference: https://github.com/samratashok/nishang
    if any(entry in content_data.lower() for entry in ["nishang"]):
        families["Nishang"][STR_INDICATORS].extend(["nishang"])

    # Family: Invoke-CradleCrafter
    # Reference:
    if any(entry in content_data.lower() for entry in ["invoke-cradlecrafter", "postcradlecommand"]):
        families["Invoke-CradleCrafter"][STR_INDICATORS].extend(["invoke-cradlecrafter", "postcradlecommand"])

    # Family: Invoke-SharpHound
    # Reference: https://github.com/BloodHoundAD/SharpHound3
    if any(entry in content_data.lower() for entry in ["invokesharphound", "sharphound"]):
        families["Invoke-SharpHound"][STR_INDICATORS].extend(["invokesharphound", "sharphound"])

    return families


###########################################
# De-obfuscation / Normalization Functions #
###########################################


def remove_null(output: Dict[str, Any], content_data, modification_flag):
    """
    Windows/Unicode introduces NULL bytes will interfere with string and REGEX pattern matching.

    Args:
        output: What is to be returned by the profiler
        content_data: "\x00H\x00e\x00l\x00l\x00o"
        modification_flag: Boolean

    Returns:
        content_data: "Hello"
        modification_flag: Boolean
    """
    output["modifications"].append(f"Removed NULLs")

    return content_data.replace("\x00", "").replace("\\x00", ""), modification_flag


def format_replace(output, content_data):
    """
    Attempts to parse PowerShell Format Operator by re-ordering substrings into the main string.
    Due to flexibility of language, it tries to identify nested versions first and unwrap it inside-out.

    Args:
        output: What is to be returned by the profiler
        content_data: 'This is an ("{1}{0}{2}" -F"AMP","EX", "LE")'

    Returns:
        content_data: 'This is an "EXAMPLE"'
        modification_flag: Boolean
    """
    try:
        # Inner most operators, may not contain strings potentially with nested format operator layers ("{").
        obf_group = re.search(
            r"\((?:\s*)(\"|\')((?:\s*){[0-9]{1,3}}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(\"|\')[^{]+?(\"|\')(?:\s*)\)",
            content_data).group()
    except Exception as e:

        try:
            # General capture of format operators without nested values.
            # Replaced LF with 0x01 simply to have a place holder to return the string back to later.
            obf_group = re.search(
                r"\((?:\s*)(\"|\')((?:\s*){[0-9]{1,3}}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(\"|\').+?(\"|\')(?:\s*)\)(?![^)])",
                content_data.replace("\n", "\x01")).group()

        except Exception as e:
            # Final attempt by removing all LF - will potentially modify input string greatly
            obf_group = re.search(
                r"\((?:\s*)(\"|\')((?:\s*){[0-9]{1,3}}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(\"|\').+?(\"|\')(?:\s*)\)(?![^)])",
                content_data.replace("\n", "")).group()

            if obf_group:
                content_data = content_data.replace("\n", "")

    built_string = format_builder(obf_group)

    content_data = content_data.replace(obf_group.replace("\x01", "\n"), '"' + built_string + '"').replace("\x01", "\n")

    output["modifications"].append("Format Replaced")

    return content_data, True


def format_builder(obf_group):
    """
    Supporting function for formatReplace() that will try to build format operator indexes and rebuild strings.

    Args:
        obf_group: '("{1}{0}{2}" -F"AMP",'EX', "LE")'

    Returns:
        content_data: 'EXAMPLE'
    """
    # Builds an index list from the placeholder digits.
    index_list = [int(x) for x in re.findall(r"\d+", obf_group.split("-")[0])]

    string_list = "-".join(obf_group.split("-")[1:])[1:-1]
    string_list = [x[0][1:-1] for x in re.findall(r"((\"|\').+?(?<!`)(\2))", string_list)]

    content_data = list()

    for entry in index_list:
        if entry < len(string_list):
            content_data.append(string_list[entry])

    content_data = "".join(content_data)

    return content_data


def remove_escape_quote(output, content_data, modification_flag):
    """
    Removes escaped quotes. These will frequently get in the way for string matching over longer structures.

    Args:
        output: What is to be returned by the profiler
        content_data: b"This is an \\"EXAMPLE\\""
        modification_flag: Boolean

    Returns:
        content_data: b'This is an "EXAMPLE"'
        modification_flag: Boolean
    """
    counter = 0

    # Replace blank quotes first so as to not cause issues with following replacements
    content_data = content_data.replace("\\'\\'", "").replace('\\"\\"', "")

    for entry in re.findall(r"([^'])(\\\')", content_data):
        content_data = content_data.replace("".join(entry), entry[0] + "'")
        modification_flag = True
        counter += 1

    for entry in re.findall(r'([^"])(\\\")', content_data):
        content_data = content_data.replace("".join(entry), entry[0] + '"')
        modification_flag = True
        counter += 1

    if modification_flag:
        output["modifications"].append(f"Removed Escaped Quotes: _ {counter}")

    return content_data, modification_flag


def remove_empty_quote(output, content_data):
    """
    Removes Empty Quotes which can be used as obfuscation to break strings apart.

    Args:
        output: What is to be returned by the profiler
        content_data: "EXA''MPLE"

    Returns:
        content_data: "EXAMPLE"
        modification_flag: Boolean
    """
    output["modifications"].append("Removed Empty Quotes")
    return content_data.replace("''", "").replace('""', ''), True


def remove_tick(output, content_data):
    """
    Removes Back Ticks which can be used as obfuscation to break strings apart.

    Args:
        output: What is to be returned by the profiler
        content_data: "$v`a`r=`'EXAMPLE'`"

    Returns:
        content_data: "$var='EXAMPLE'"
        modification_flag: Boolean
    """
    output["modifications"].append("Removed Back Ticks")
    return content_data.replace("`", ""), True


def remove_caret(output, content_data):
    """
    Removes Caret which can be used as obfuscation to break strings apart.

    Args:
        output: What is to be returned by the profiler
        content_data: "$v^a^r=^'EXAMPLE'^"

    Returns:
        content_data: "$var='EXAMPLE'"
        modification_flag: Boolean
    """
    output["modifications"].append("Removed Carets")
    return content_data.replace("^", ""), True


def space_replace(output, content_data, modification_flag):
    """
    Converts two spaces to one.

    Args:
        output: What is to be returned by the profiler
        content_data: "$var=    'EXAMPLE'"
        modification_flag:

    Returns:
        output: What is to be returned by the profiler
        content_data: "$var= 'EXAMPLE'"
        modification_flag: Boolean
    """
    output["modifications"].append("Converted double spaces to single spaces")
    return content_data.replace("  ", " "), modification_flag


def char_replace(output, content_data, modification_flag):
    """
    Attempts to convert PowerShell char data types using Hex and Int values into ASCII.

    Args:
        output: What is to be returned by the profiler
        content_data: [char]101
        modification_flag: Boolean

    Returns:
        content_data: "e"
        modification_flag: Boolean
    """
    #  Hex needs to go first otherwise the 0x gets gobbled by second Int loop/PCRE (0x41 -> 65 -> "A")
    for value in re.findall(r"\[char]0x[0-9a-z]{1,2}", content_data):
        char_convert = int(value.split("]")[1], 0)
        if 10 <= char_convert <= 127:
            content_data = content_data.replace(value, '"%s"' % chr(char_convert))
            modification_flag = True

    # Int values
    for value in re.findall(r"\[char][0-9]{1,3}", content_data, re.IGNORECASE):
        char_convert = int(value.split("]")[1])
        if 10 <= char_convert <= 127:
            content_data = content_data.replace(value, '"%s"' % chr(char_convert))
            modification_flag = True

    if modification_flag:
        output["modifications"].append("CharReplace")

    return content_data, modification_flag


def type_conversion(output, content_data, modification_flag):
    """
    Attempts to identify Int (various bases), 0xHex, and \\xHex formats in comma-delimited lists for conversion to ASCII.

    Args:
        output: What is to be returned by the profiler
        content_data: "69,88,65,77,80,76,69"
        modification_flag: Boolean

    Returns:
        content_data: "EXAMPLE"
        modification_flag: Boolean
    """
    counter = 0

    for baseValue in [0, 8, 16, 32]:

        base_string = str()

        for entry in re.findall(
            r"([1-2]?[0-9][0-9](?:\s*),|0x[0-9a-fA-F]{1,2}(?:\s*),|\\x[0-9a-fA-F]{1,2}(?:\s*),)", content_data.replace(
                " ", "")):
            entry = re.search("[A-Fa-f0-9]+", entry.replace("0x", "")).group()
            if entry != "0":
                try:
                    counter += 1
                    char_convert = int(entry, baseValue)
                    if 10 <= char_convert <= 127:
                        base_string += chr(char_convert)
                except Exception as e:
                    pass

        base_string = strip_ascii(base_string)

        # Additional checks to make sure we're not in a loop
        if base_string not in garbage_list and not any(
                x in base_string for x in garbage_list) and len(base_string) > 50:
            content_data += "\n\n##### TYPE CONVERSION #####\n\n%s\n\n" % (base_string)
            garbage_list.append(base_string)
            modification_flag = True

    if modification_flag:
        output["modifications"].append(f"Type Conversion _ {counter}")

    return content_data, modification_flag


def string_split(output, content_data, modification_flag):
    """
    Attempts to split strings and combine them back with a comma.
    Primarily targeting lists of bytes for type conversion.

    Args:
        output: What is to be returned by the profiler
        content_data: "HAeBlBlCo".split("ABC")
        modification_flag: Boolean

    Returns:
        content_data: "H,e,l,l,o"
        modification_flag: Boolean
    """
    split_string = re.search(r"\.split\((\'|\")[^\'\"]+?\1\)", content_data, re.IGNORECASE).group()
    delim_split = [x for x in split_string[8:-2]]
    check_strings = re.findall(r"((\'|\")[^\2]+?\2)", content_data)

    if delim_split != [] and delim_split != [" "] and len(delim_split) < 10:
        content_data = content_data.replace(split_string, "")

        for entry in check_strings:
            stripped_string = entry[0][1:-1]
            for x in delim_split:
                if x in entry[0]:
                    # Sets to "comma" as a separator so typeConversion can pick it up on next run
                    stripped_string = stripped_string.replace(x, ",")

                    if stripped_string not in garbage_list and stripped_string != ",":
                        garbage_list.append(entry[0])
                        content_data += "\n\n##### SPLIT STRINGS #####\n\n%s\n\n" % (stripped_string)
                        modification_flag = True

    if modification_flag:
        output["modifications"].append("Split Strings")

    return content_data, modification_flag


def join_strings(output, content_data, modification_flag):
    """
    Joins strings together where a quote is followed by a concatenation and another quote.

    Args:
        output: What is to be returned by the profiler
        content_data: "$var=('EX'+'AMP'+'LE')"
        modification_flag: Boolean

    Returns:
        content_data: "$var=('EXAMPLE')"
        modification_flag: Boolean
    """
    for entry in re.findall(r"(?:\"|\')(?:\s*)\+(?:\s*)(?:\"|\')", content_data):
        content_data = content_data.replace(entry, "")
        modification_flag = True

    if modification_flag:
        output["modifications"].append("Joined Strings")

    return content_data, modification_flag


def replace_decoder(output, content_data):
    """
    Attempts to replace strings across the content that use the Replace function.

    Args:
        output: What is to be returned by the profiler
        content_data: "(set GmBtestGmb).replace('GmB',[Char]39)"

    Returns:
        content_data: "set 'test'"
        modification_flag: Boolean
    """
    # Clean up any chars or byte values before replacing
    content_data, modification_flag = char_replace(output, content_data, None)

    # Group 0 = Full Line, Group 3 = First, Group 6 = Second.
    # Second replace can be empty so * instead of +, first may never be empty.
    replace_strings = re.findall(
        r"((?:\.replace)(?:\s*)\(?(?:\s*)\(?(?:([^(\'|\")])*)(\'|\")([^\3]*?)\3(?:[^,]*?),(?:\s*)\(?(?:([^(\'|\")])*)(\'|\")([^\6]*?)\6(?:\s*)\)?(?:\s*)\)?)",
        content_data, re.IGNORECASE)

    for entry in replace_strings:
        # Length check to compensate for replace statements without a defined replacement.
        # Without length check, when it defaults to nothing, it can cause REGEX pattern to over match.
        if entry[3] != "" and entry[0] not in garbage_list and len(entry[0]) < 30:
            garbage_list.append(entry[0])
            content_data = content_data.replace(entry[0], "")
            output["modifications"].append(f"Replaced Strings - '{entry[0]}' with ''")
            content_data = content_data.replace(entry[3], entry[6])
            output["modifications"].append(f"Replaced Strings - '{entry[3]}' with '{entry[6]}'")
            modification_flag = True

    return content_data, modification_flag


def replace_powershell(output, content_data, modification_flag):
    """
    Attempts to replace strings across the content that use the PowerShell command.

    Args:
        content_data: "POWERSHELL $SOS='blah';"
        modification_flag: Boolean

    Returns:
        output: What is to be returned by the profiler
        content_data: "$SOS='blah';"
        modification_flag: Boolean
    """
    for entry in re.findall(r"powershell\s*", content_data, re.IGNORECASE):
        content_data = content_data.replace(entry, "")
        modification_flag = True

    if modification_flag:
        output["modifications"].append("Removed PowerShell command")

    return content_data, modification_flag

########################
# Unraveling Functions #
########################


def reverse_strings(output, original_data, content_data, modification_flag):
    """
    Reverses content and appends it to the modified data blob.

    Args:
        output: What is to be returned by the profiler
        original_data: marap
        content_data: example
        modification_flag: Boolean

    Returns:
        content_data: example param
        modification_flag: Boolean

    """
    reverse_msg = original_data[::-1]

    if reverse_msg not in garbage_list:
        content_data += f"\n\n##### REVERSED CONTENT #####\n\n{reverse_msg}\n\n"
        garbage_list.append(reverse_msg)
        modification_flag = True

    if modification_flag:
        output["modifications"].append(f"Reversed Strings")

    return content_data, modification_flag


def decompress_content(output, content_data, modification_flag):
    """
    Attempts to decompress content using various algorithms (zlib/gzip/etc).

    Args:
        output: What is to be returned by the profiler
        content_data: String of Base64 content
        modification_flag: Boolean

    Returns:
        content_data: Decompressed content of ASCII printable
    """
    for entry in re.findall(r"[A-Za-z0-9+/=]{40,}", content_data):
        try:  # Wrapped in try/except because both strings can appear but pipe through unrelated Base64.
            decompress_msg = decompress_data(entry)
            if decompress_msg and decompress_msg != entry:
                if decompress_msg not in garbage_list:
                    content_data += "\n\n##### DECOMPRESS CONTENT #####\n\n%s\n\n" % (decompress_msg)
                    garbage_list.append(decompress_msg)
                    modification_flag = True

                    # Add decompressed data to be extracted later
                    if all(item in decompress_msg for item in ["MZ", "This program cannot be run in DOS mode"]):
                        output["extracted"].append({"type": "decompressed", "data": decompress_msg.encode()})
        except Exception as e:
            pass

    if modification_flag:
        output["modifications"].append("Decompressed Content")

    return content_data, modification_flag


def decompress_data(content_data):
    """
    Handles the actual decompression of Base64 data.

    Args:
        content_data: String of Base64 content

    Returns:
        content_data: Decompressed content of ASCII printable

    """
    decoded = base64.b64decode(content_data)
    # IO.Compression.DeflateStream
    try:
        # 15 is the default parameter
        content_data = zlib.decompress(decoded, 15)  # zlib
    except Exception as e:
        pass
    try:
        # -15 makes it ignore the gzip header
        content_data = zlib.decompress(decoded, -15)  # zlib
    except Exception as e:
        pass
    try:
        content_data = zlib.decompress(decoded, -zlib.MAX_WBITS)  # deflate
    except Exception as e:
        pass
    try:
        content_data = zlib.decompress(decoded, 16 + zlib.MAX_WBITS)  # gzip
    except Exception as e:
        pass

    content_data = strip_ascii(content_data)

    return content_data


def decode_base64(output, entries, modification_flag):
    """
    Attempts to decode Base64 content.

    Args:
        output: What is to be returned by the profiler
        entries: A dictionary with the original base64 encoded sections as keys
        and the corresponding decoded data as values
        modification_flag: Boolean

    Returns:
        content_data: Decoded Base64 string
        modification_flag: Boolean
    """
    for entry, decoded in entries.items():
        try:
            # In instances where we have a broken/fragmented Base64 string.
            # Try to subtract to the lower boundary than attempting to add padding.
            while len(entry) % 4:
                entry = entry[:-1]
            base_string = strip_ascii(decoded)

            # Require a minimum length for encoded and decoded values
            if entry and entry.decode() not in garbage_list and len(entry) > 50 and len(base_string) > 16:
                output["extracted"].append({"type": "base64_decoded", "data": decoded})
                garbage_list.append(entry.decode())
                modification_flag = True
        except Exception as e:
            pass

    if modification_flag:
        output["modifications"].append("Decoded Base64")

    return modification_flag


def decrypt_strings(output, content_data, modification_flag):
    """
    Attempts to decrypt Microsoft SecureStrings using AES-CBC.

    Args:
        output: What is to be returned by the profiler
        content_data: Content with key and encrypted SecureString
        modification_flag: Boolean

    Returns:
        content_data: Decrypted content
        modification_flag: Boolean
    """
    for entry in re.findall(r"[A-Za-z0-9+/=]{250,}", content_data):
        try:  # Wrapped in try/except since we're effectively brute forcing

            for key in re.findall(r"(?:[0-9]{1,3},){15,}[0-9]{1,3}", content_data.replace(" ", "")):

                decompress_msg = decrypt_data(entry, key)
                if decompress_msg:
                    if decompress_msg not in garbage_list:
                        content_data += f"\n\n##### DECRYPTED CONTENT #####\n\n{decompress_msg}\n\n"
                        garbage_list.append(decompress_msg)
                        modification_flag = True
        except Exception as e:
            pass

    if modification_flag:
        output["modifications"].append("Decrypted Content")

    return content_data, modification_flag


def decrypt_data(content_data, key):
    """
    Handles the actual AES-CBC decryption.

    Args:
        content_data: SecureString Base64 Content (contains IV and encrypted data)
        key: AES CBC Key

    Returns:
        content_data: Decrypted content
    """
    # Possibly a better indicator "76492d1116743f0" for start header of Base64 content using this method.

    data = base64.b64decode(content_data)
    data = data.replace(b"\x00", b"")
    data = data.split(b"|")

    iv = base64.b64decode(data[1])
    data = binascii.unhexlify(data[2])
    key = "".join([chr(y) for y in [int(x) for x in key.split(",")]])
    key = key.encode("raw_unicode_escape")

    decrypt = AES.new(key, AES.MODE_CBC, iv)
    decrypt = decrypt.decrypt(data)

    content_data = decrypt.replace(b"\x00", b"").decode().strip()

    return content_data


########################
# Processing Functions #
########################


def normalize(output: Dict[str, Any], content_data):
    """
    The primary normalization and de-obfuscation function. Runs various checks and changes as necessary.

    Args:
        output: What is to be returned by the profiler
        content_data: Script content

    Returns:
        content_data: Normalized / De-Obfuscated content
    """

    # Passes modification_flag to each function to determine whether or not it should try to normalize the new content.
    while True:
        modification_flag = None

        # Remove Null Bytes - Changes STATE
        # Keep this one first so that further PCRE work as expected.
        if re.search(r"(\x00|\\\\x00)", content_data):
            content_data, modification_flag = remove_null(output, content_data, modification_flag)

        # Rebuild format operator replacements - Changes STATE
        while re.search(
                r'\((?:\s*)(\"|\')((?:\s*){[0-9]{1,3}}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(?!.*{\d})(?:(\"|\').+?(\"|\'))(?:\s*)\)',
                content_data) or re.search(
            r'\((?:\s*)(\"|\')((?:\s*){[0-9]{1,3}}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(\"|\').+?(\"|\')(?:\s*)\)',
                content_data.replace("\n", "")):
            content_data, modification_flag = format_replace(output, content_data)

        # Un-Escape Quotes - Changes STATE
        if re.search(r"([^'])(\\')", content_data) or re.search(r'([^"])(\\")', content_data):
            content_data, modification_flag = remove_escape_quote(output, content_data, modification_flag)

        # Remove Empty Quotes - Changes STATE
        if "''" in content_data or '""' in content_data:
            content_data, modification_flag = remove_empty_quote(output, content_data)

        # Remove Back Tick - Changes STATE
        if "`" in content_data:
            content_data, modification_flag = remove_tick(output, content_data)

        # Remove Caret - Changes STATE
        if "^" in content_data:
            content_data, modification_flag = remove_caret(output, content_data)

        # While this makes the file look beautiful, it is not worth extracting a file over
        # Removes Space Padding - Does NOT change STATE
        # while re.search(r"[\x20]{2,}", content_data):
        #     content_data, modification_flag = space_replace(output, content_data, modification_flag)

        # Converts Char bytes to ASCII - Changes STATE
        if re.search(r"\[char](0x)?[0-9A-Fa-f]{1,3}", content_data, re.IGNORECASE):
            content_data, modification_flag = char_replace(output, content_data, modification_flag)

        # Commenting out since this usually produces junk
        # Type conversions - Changes STATE
        # if re.search(
        #         r"([1-2]?[0-9]?[0-9](?:\s*),|0x[0-9a-fA-F]{1,2}(?:\s*),|\\x[0-9a-fA-F]{1,2}(?:\s*),)", content_data):
        #     # If a large compressed embedded file is attempted to be decompressed, the service will timeout...
        #     if len(content_data) >= 1000000 or len(re.findall(r"(\n|\r\n)", content_data)) >= 5000:
        #         pass
        #     else:
        #         content_data, modification_flag = type_conversion(output, content_data, modification_flag)

        # This creates an unnecessary file in the file tree since this type of string manipulation is not
        # Overpower's job
        # String Splits - Changes STATE
        # if re.search(r"\.split\((\'|\")[^\'\"]+?\1\)", content_data, re.IGNORECASE):
        #     content_data, modification_flag = string_split(output, content_data, modification_flag)

        # Bridge strings together - Changes STATE
        if re.search(r"(\"|\')(?:\s*)\+(?:\s*)(\"|\')", content_data):
            content_data, modification_flag = join_strings(output, content_data, modification_flag)

        # Replace strings - Changes STATE
        # Leave this one last after other formatting has completed
        if re.search(
                r'((?:replace)(?:\s*)\((?:\s*)\(?(?:([^(\'|\")])*)(\'|\")([^(\3)]+?)\3(?:[^,]*?),(?:\s*)'
                r'\(?(?:([^(\'|\")])*)(\'|\")([^(\6)]*?)\6(?:\s*)\)?(?:\s*)\))',
                content_data, re.IGNORECASE):
            content_data, modification_flag = replace_decoder(output, content_data)

        # Remove PowerShell command
        if re.search(r"powershell\s*", content_data, re.IGNORECASE):
            content_data, modification_flag = replace_powershell(output, content_data, modification_flag)

        if modification_flag is None:
            break

    return content_data


def unravel_content(output, original_data):
    """
    This is the primary function responsible for creating an alternate data stream of unraveled data.

    Args:
        output: What is to be returned by the profiler
        original_data: Script content

    Returns:
        content_data: Unraveled additional content
    """
    content_data = normalize(output, original_data)
    loop_count = 0

    while True:

        modification_flag = None

        # Reversed Strings - Changes STATE
        # Looks only in original_data, can be problematic flipping unraveled content back and forth.
        reverse_string = ["noitcnuf", "marap", "nruter", "elbairav", "tcejbo-wen", "ecalper"]
        if any(entry in original_data.lower() for entry in reverse_string):
            content_data, modification_flag = reverse_strings(output, original_data, content_data, modification_flag)

        # Decompress Streams - Changes STATE
        if all(entry in content_data.lower() for entry in ["streamreader", "frombase64string"]) or \
                all(entry in content_data.lower() for entry in ["deflatestream", "decompress"]) or \
                all(entry in content_data.lower() for entry in ["memorystream", "frombase64string"]):
            # If a large compressed embedded file is attempted to be decompressed, the service will timeout...
            if len(content_data) >= 1000000 or len(re.findall(r"(\n|\r\n)", content_data)) >= 5000:
                pass
            else:
                content_data, modification_flag = decompress_content(output, content_data, modification_flag)

        # Base64 Decodes - Changes STATE
        entries = base64_search(content_data.encode())
        if len(entries):
            # If a large compressed embedded file is attempted to be decompressed, the service will timeout...
            if len(content_data) >= 1000000 or len(re.findall(r"(\n|\r\n)", content_data)) >= 5000:
                pass
            else:
                modification_flag = decode_base64(output, entries, modification_flag)

        # Decrypts SecureStrings - Changes STATE
        if "convertto-securestring" in content_data.lower() and \
                re.search(r"(?:[0-9]{1,3},){15,}[0-9]{1,3}", content_data.replace(" ", "")) and \
                re.search(r"[A-Za-z0-9+=/]{255,}", content_data):
            content_data, modification_flag = decrypt_strings(output, content_data, modification_flag)

        # Normalize / De-Obfuscate the new contents before proceeding.
        content_data = normalize(output, content_data)

        if modification_flag is None:
            break

        loop_count += 1

    return content_data


def profile_ps1(sample_path, working_dir):
    global garbage_list
    garbage_list = list()
    output: Dict[str, Any] = {
        "behaviour": {"commands": [], "tags": []},
        "deobfuscated": None,
        "families": [],
        "modifications": [],
        "score": 0,
        "verdict": None,
        "extracted": []
    }

    # Setup behaviour_tags dict so behaviours can be tracked throughout processing
    behaviour_tags: Dict[str, Any] = {}

    # Open file for processing, ignore errors
    with open(sample_path, "rb") as fh:
        try:
            original_data = fh.read().decode()
        except UnicodeDecodeError as e:
            print(f"Could not decode {sample_path} due to {e}.")
            original_data = ""

    # Strip NULLs out before processing
    original_data = original_data.replace("\x00", "")

    # Launches the primary unraveling loop to begin cleaning up the script for profiling.
    alternative_data = f"{unravel_content(output, original_data)}"
    output["deobfuscated"] = alternative_data

    # Launches family specific profiling function over original_data and alternative_data
    families = family_finder(original_data + alternative_data)
    if len(families) > 0:
        output["families"] = families

    # Launches behavioural profiling over original_data and alternative_data
    behaviour_tags = profile_behaviours(behaviour_tags, original_data, alternative_data)

    # Score the behaviours and print final results
    score, verdict, behaviour_tags = score_behaviours(behaviour_tags)
    output["score"] = score
    output["verdict"] = verdict
    output["behaviour"] = behaviour_tags

    # Write what we've parsed out for further analysis
    alt_data = os.path.join(working_dir, DEOBFUS_FILE)
    with open(alt_data, "w") as f:
        f.write(output["deobfuscated"].rstrip())

    return output
