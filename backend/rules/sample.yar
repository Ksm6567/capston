rule PE_Process_Injection_Toolmark { strings: =\" "VirtualAllocEx\ ascii wide =\WriteProcessMemory\ ascii wide =\CreateRemoteThread\ ascii wide =\NtUnmapViewOfSection\ ascii wide condition: uint16(0) == 0x5A4D and 3 of (*) } 
rule Mock_Hacker_Testing { strings: =\" "HACKER_DETECTED\ ascii wide condition:  } 
rule Suspicious_PowerShell_Loader { strings: =\" "powershell\ ascii wide nocase =\-enc\ ascii wide nocase =\FromBase64String\ ascii wide nocase =\Invoke-Expression\ ascii wide nocase =\Net.WebClient\ ascii wide nocase =\DownloadString\ ascii wide nocase condition:  and 2 of (,,,,) } 
