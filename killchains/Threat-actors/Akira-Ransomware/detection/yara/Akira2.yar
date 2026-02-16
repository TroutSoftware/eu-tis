/*
akira ransomware
*/

rule Akira_Ransomware_Commands
{
    meta:
        description = "Detect Akira Ransomware commands"
        author = "yaouilo"
        last_modified = "2024-11-18"
        threat_level = "high"

    strings:
        $nltest_dclist = "nltest /dclist" nocase
        $net_group_admins = "net group \"Domain admins\" /dom" nocase
        $tasklist = "tasklist" nocase
        $rundll32_lsass = "rundll32.exe c:\\Windows\\System32\\comsvcs.dll, MiniDump" nocase
        $chrome_credentials = "esentutl.exe /y" nocase
        $firefox_credentials = "key4.db" nocase
        $shadowcopy_remove = "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject" nocase

    condition:
        any of ($nltest_dclist, $net_group_admins, $tasklist, $rundll32_lsass, $chrome_credentials, $firefox_credentials, $shadowcopy_remove)
}
