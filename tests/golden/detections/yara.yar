// Built by dirsift from a scan of hxxp://panel-gate[.]xyz/files/
// Run golden-run, 2026-10-01, TLP:AMBER
// Each rule matches on the indicators its file carried. The digests are in
// meta: identity for the sample the indicators came from, not the condition.
rule dirsift_golden_run_loader_sh
{
    meta:
        author = "cyb3rp03t"
        tool = "dirsift"
        run = "golden-run"
        target = "hxxp://panel-gate[.]xyz/files/"
        file = "loader.sh"
        created = "2026-10-01"
        tlp = "TLP:AMBER"
        sha256 = "9f2c1b7d3e4a5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
        md5 = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        caveat = "Built from the bytes the scan read, which is the head of the file rather than the whole of it."
    strings:
        $url1 = "http://c2.evil-update.top/gate.php?id=1&k=*" ascii
        $mail1 = "ops@evil-update.top" ascii
        $dom1 = "cdn.panel-gate.xyz" ascii
        $ip1 = "203.0.113.9:4444" ascii
        $ip2 = "8.8.8.8" ascii
    condition:
        2 of them
}
