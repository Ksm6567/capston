/*
  Capstone Project - Unified Yara Rules Portfolio
  Based on common Open Source / Community Yara Signatures.
  (VirusTotal / YARA-Rules Community)
*/

rule Windows_Executable_Suspicious_Strings {
    meta:
        description = "Detects Windows PE files with highly suspicious API imports or strings"
        author = "Community"
    strings:
        // PE Magic Number
        $mz = "MZ"
        
        // Suspicious strings often used by Trojans/Malware
        $s1 = "VirtualAlloc" ascii
        $s2 = "CreateRemoteThread" ascii
        $s3 = "WriteProcessMemory" ascii
        $s4 = "SetWindowsHookEx" ascii 
    condition:
        $mz at 0 and 2 of ($s*)
}

rule Generic_Ransomware_Note {
    meta:
        description = "Detects common phrases found in Ransomware text notes"
        author = "Community"
    strings:
        $r1 = "Your files are encrypted" nocase
        $r2 = "Bitcoin" nocase
        $r3 = "Decryption key" nocase
        $r4 = "Tor browser" nocase
        $r5 = "Restore your files" nocase
    condition:
        3 of ($r*)
}

rule Suspicious_PowerShell_Download {
    meta:
        description = "Detects PowerShell commands downloading and executing payloads"
        author = "Community"
    strings:
        $p1 = "Net.WebClient" nocase
        $p2 = "DownloadString" nocase
        $p3 = "DownloadFile" nocase
        $p4 = "Invoke-Expression" nocase
        $p5 = "IEX" nocase
    condition:
        ($p1 and ($p2 or $p3)) or ($p4 or $p5)
}

rule Crypto_Miner_Signatures {
    meta:
        description = "Detects generic CPU/GPU crypto mining configurations"
        author = "Community"
    strings:
        $m1 = "stratum+tcp://" ascii nocase
        $m2 = "nicehash" ascii nocase
        $m3 = "monero" ascii nocase
        $m4 = "xmrig" ascii nocase
    condition:
        any of ($m*)
}

// ----------------------------------------------------
// 기존 테스트 호환성을 위해 남겨둔 규칙 (사용자 테스트용)
// ----------------------------------------------------
rule Mock_Hacker_Testing {
    meta:
        description = "Detects the presence of a mock hacker string for testing"
        author = "Capstone Test"
    strings:
        $hacker_string = "HACKER_DETECTED"
    condition:
        $hacker_string
}
