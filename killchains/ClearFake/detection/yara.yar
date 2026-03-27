rule ClearFake_Campaign_Loader_And_Payload
{
    meta:
        description = "Detects ClearFake loader and downstream payload artifacts based on execution patterns, obfuscation, and anti-analysis behavior"
        author = "EU-TIS Community"
        date = "2026-01-29"
        reference = "https://www.bridewell.com/insights/blogs/detail/clearfake-campaign"
        malware_family = "ClearFake"
        confidence = "medium"

    strings:
        /* PowerShell encoded execution (user-assisted / ChromeLoader style) */
        $ps_enc_1 = "-enc" ascii nocase
        $ps_enc_2 = "Start-Sleep" ascii nocase

        /* Anti-VM / sandbox check via WMI */
        $wmi_temp = "MSAcpi_ThermalZoneTemperature" ascii

        /* Persistence via scheduled task (Amadey downstream) */
        $schtasks_1 = "schtasks.exe" ascii nocase
        $schtasks_2 = "/Create" ascii nocase
        $schtasks_3 = "/SC" ascii nocase

        /* Common masquerading / loader artifacts */
        $loader_name_1 = "ChromeSetup.exe" ascii nocase
        $loader_name_2 = "MicrosoftEdgeSetup.exe" ascii nocase

    condition:
        (
            /* Encoded PowerShell execution */
            ( $ps_enc_1 and $ps_enc_2 )
        )
        or
        (
            /* Sandbox evasion via WMI temperature query */
            $wmi_temp
        )
        or
        (
            /* Persistence creation using scheduled tasks */
            all of ($schtasks_*)
        )
}
