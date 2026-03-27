rule Lumma_FakeCaptcha_Loader_And_C2
{
    meta:
        description = "Detects binaries related to a Lumma-like fake CAPTCHA infection chain (AF1.exe, afc.zip, deci.com, C2 domains)"
        author = "Adelina Comanescu"
        date = "2025-11-25"
        reference = "Internal SOC simulation – Lumma fake CAPTCHA"
        malware_family = "LummaStealer"
        tlp = "GREEN"

    strings:
        // Filenames / components seen in the chain
        $fname_afc      = "afc.zip" ascii
        $fname_af1      = "AF1.exe" ascii
        $fname_deci     = "deci.com" ascii
        $dll_iconx      = "IconX.dll" ascii
        $dll_dx0        = "dx0.dll" ascii
        $dll_directgui  = "DirectGUI.dll" ascii

        // C2 domains used in the campaign
        $c2_main        = "blameaowi.run" ascii
        $c2_alt1        = "flowerexju.bet" ascii
        $c2_alt2        = "mzmedtipp.live" ascii
        $c2_alt3        = "easterxeen.run" ascii
        $c2_alt4        = "araucahkbm.live" ascii
        $c2_alt5        = "overcovtcg.top" ascii
        $c2_alt6        = "blackswmxc.top" ascii
        $c2_alt7        = "posseswsnc.top" ascii
        $c2_alt8        = "4featurlyin.top" ascii

    condition:
        // Stronger detection when both local component names and at least one C2 are present
        (
            ( $fname_af1 or $fname_afc or $fname_deci ) and
            ( $c2_main or $c2_alt1 or $c2_alt2 or $c2_alt3 or $c2_alt4 or $c2_alt5 or $c2_alt6 or $c2_alt7 or $c2_alt8 )
        )
        or
        // Or any combination of two C2s in the same binary (rare in benign files)
        ( 2 of ($c2_main, $c2_alt1, $c2_alt2, $c2_alt3, $c2_alt4, $c2_alt5, $c2_alt6, $c2_alt7, $c2_alt8) )
}
