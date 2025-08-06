rule win_elise_w0 {
    meta:
        author = "ThreatConnect Intelligence Research Team - Wes Hurd"
        license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."
        source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/Elise.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.elise"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $0E = "\\000ELISEA"
        $D = "~DF37382D8F2E.tmp" nocase wide ascii
        $SE = "SetElise.pdb" wide ascii
        $xpage = "/%x/page_%02d%02d%02d%02d.html" wide ascii
    condition:
        any of them
}
