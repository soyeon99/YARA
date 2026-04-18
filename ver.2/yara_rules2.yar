rule Suspicious_PE_Executable {
    meta:
        description = "의심스러운 PE 실행파일"
        author = "CAPE Scanner"
        
    strings:
        $pe_header = "PE32"
        $suspicious_api1 = "CreateRemoteThread"
        $suspicious_api2 = "VirtualAllocEx" 
        $suspicious_api3 = "WriteProcessMemory"
        
    condition:
        $pe_header and 2 of ($suspicious_api*)
}

rule Malicious_PDF {
    meta:
        description = "악성 PDF 문서"
        author = "CAPE Scanner"
        
    strings:
        $pdf_header = "PDF document"
        $js_embed = "JavaScript"
        $suspicious_obj = "/OpenAction"
        $suspicious_stream = "FlateDecode"
        
    condition:
        $pdf_header and ($js_embed or ($suspicious_obj and $suspicious_stream))
}

rule Obfuscated_JavaScript {
    meta:
        description = "난독화된 자바스크립트"
        author = "CAPE Scanner"
        
    strings:
        $js_indicator = "ASCII text"
        $long_lines = "very long lines"
        $obfuscation1 = "eval"
        $obfuscation2 = "unescape"
        $obfuscation3 = "fromCharCode"
        
    condition:
        $js_indicator and $long_lines and 1 of ($obfuscation*)
}

rule Suspicious_MSI_Installer {
    meta:
        description = "의심스러운 MSI 설치파일"
        author = "CAPE Scanner"
        
    strings:
        $msi_header = "MSI Installer"
        $wix_toolset = "WiX Toolset"
        $random_name = /[A-Za-z0-9]{10,}/
        
    condition:
        $msi_header and $wix_toolset
}

rule Malicious_LNK_File {
    meta:
        description = "악성 바로가기 파일"
        author = "CAPE Scanner"
        
    strings:
        $lnk_header = "MS Windows shortcut"
        $mshta_exe = "mshta.exe"
        $powershell = "powershell"
        $suspicious_args = "command line arguments"
        
    condition:
        $lnk_header and ($mshta_exe or $powershell) and $suspicious_args
}

rule Encrypted_Archive {
    meta:
        description = "암호화된 압축파일"
        author = "CAPE Scanner"
        
    strings:
        $zip_header = "Zip archive"
        $aes_encrypted = "AES Encrypted"
        
    condition:
        $zip_header and $aes_encrypted
}

rule Known_Malware_Hash {
    meta:
        description = "알려진 악성코드 해시"
        author = "CAPE Scanner"
        
    strings:
        // 실제 악성코드 해시들
        $hash1 = "5646873f89e3468c306385ef3d65b7daf63aeee4128553c3224c75cb0e6902ca"
        $hash2 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2"
        $hash3 = "46713fa0caa7ad73ab2558456bdb0af41ed18e5c91d4622e4cbe998da501d45f"
        
    condition:
        any of ($hash*)
}

rule Suspicious_Unicode_Script {
    meta:
        description = "의심스러운 유니코드 스크립트"
        author = "CAPE Scanner"
        
    strings:
        $unicode = "Unicode text"
        $utf16 = "UTF-16"
        $very_long = "very long lines"
        
    condition:
        $unicode and $utf16 and $very_long
}