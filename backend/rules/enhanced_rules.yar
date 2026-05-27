rule Capstone_Safe_Yara_Test_Incident {
    meta:
        description = "Safe Capstone EDR test marker for incident workflow validation"
        tier = "local-critical"
        severity = "critical"
        safe_test = "true"
    strings:
        $marker = "CAPSTONE_EDR_SAFE_YARA_TEST_INCIDENT" ascii wide
    condition:
        filesize < 64KB and $marker
}

rule Capstone_Safe_IP_Block_Test_Script {
    meta:
        description = "Safe Capstone EDR IP block workflow test script marker"
        tier = "local-critical"
        severity = "high"
        safe_test = "true"
    strings:
        $marker = "CAPSTONE_SAFE_IP_BLOCK_TEST" ascii wide
        $label = "[Capstone IP Block Test]" ascii wide
        $tcp = "System.Net.Sockets.TcpClient" ascii wide
    condition:
        filesize < 64KB and $marker and $label and $tcp
}

rule Critical_ProcessInjection_Implant {
    meta:
        description = "Always-on critical PE process injection pattern"
        tier = "local-critical"
        severity = "critical"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtUnmapViewOfSection" ascii wide
        $api5 = "QueueUserAPC" ascii wide
        $api6 = "SetThreadContext" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 25MB and 5 of ($api*)
}

rule Critical_Ransomware_Note {
    meta:
        description = "Always-on critical ransom note with encryption, recovery, anonymity, and payment markers"
        tier = "local-critical"
        severity = "critical"
    strings:
        $enc1 = "your files are encrypted" ascii wide nocase
        $enc2 = "all your files have been encrypted" ascii wide nocase
        $recover1 = "decryption key" ascii wide nocase
        $recover2 = "restore your files" ascii wide nocase
        $anon1 = "tor browser" ascii wide nocase
        $anon2 = ".onion" ascii wide nocase
        $pay1 = "bitcoin" ascii wide nocase
        $pay2 = "monero" ascii wide nocase
    condition:
        filesize < 2MB and
        any of ($enc*) and
        any of ($recover*) and
        any of ($anon*) and
        any of ($pay*)
}

rule Critical_Mimikatz_Credential_Dumper {
    meta:
        description = "Always-on critical Mimikatz-style credential dumping markers"
        tier = "local-critical"
        severity = "critical"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii wide nocase
        $m2 = "mimikatz" ascii wide nocase
        $m3 = "privilege::debug" ascii wide nocase
        $m4 = "lsadump::sam" ascii wide nocase
        $api1 = "MiniDumpWriteDump" ascii wide
        $target1 = "lsass.exe" ascii wide nocase
    condition:
        (uint16(0) == 0x5A4D and filesize < 50MB and 2 of ($m*)) or
        (uint16(0) == 0x5A4D and filesize < 50MB and $api1 and $target1 and any of ($m*))
}

rule Critical_PowerShell_Download_Cradle {
    meta:
        description = "Always-on critical encoded PowerShell download cradle with execution"
        tier = "local-critical"
        severity = "critical"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-encodedcommand" ascii wide nocase
        $decode = "FromBase64String" ascii wide nocase
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX" ascii wide
        $web1 = "Net.WebClient" ascii wide nocase
        $web2 = "DownloadString" ascii wide nocase
        $web3 = "DownloadFile" ascii wide nocase
        $url1 = "http://" ascii wide nocase
        $url2 = "https://" ascii wide nocase
    condition:
        filesize < 5MB and
        $ps and
        any of ($enc*) and
        ($decode or any of ($exec*)) and
        any of ($web*) and
        any of ($url*)
}
