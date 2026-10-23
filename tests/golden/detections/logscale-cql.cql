// dirsift CQL hunting queries (Falcon LogScale, Next-Gen SIEM)
// dirsift run golden-run | author cyb3rp03t | TLP:AMBER
// target hxxp://panel-gate[.]xyz/files/ | scan started 2026-10-01T09:00:00.000Z
// Found in an open directory, not a verdict: hunt with it, decide yourself.
// assumes Falcon sensor events (NetworkConnectIP4/IP6, DnsRequest, ProcessRollup2) and ECS style fields for third party data in Next-Gen SIEM (destination.ip, dns.question.name, url.original)
// assumes the time range is the one set in the search page
// live values, not defanged: import it, do not open it in a browser or paste it in a chat.
// 1 URL(s) hold a * that CQL reads as a wildcard

// Falcon: connections to IPv4 addresses found in the directory
#event_simpleName=NetworkConnectIP4
| in(field=RemoteAddressIP4, values=["198.51.100.23", "203.0.113.9"])

// Falcon: connections to IPv6 addresses found in the directory
#event_simpleName=NetworkConnectIP6
| in(field=RemoteAddressIP6, values=["2001:db8::7"], ignoreCase=true)

// Falcon: DNS requests for domains found in the directory, and their subdomains
#event_simpleName=DnsRequest
| in(field=DomainName, values=["c2.evil-update.top", "cdn.panel-gate.xyz", "panel-gate.xyz", "*.c2.evil-update.top", "*.cdn.panel-gate.xyz", "*.panel-gate.xyz"], ignoreCase=true)

// Falcon: processes started from files read whole in the directory (SHA256HashData)
#event_simpleName=ProcessRollup2
| in(field=SHA256HashData, values=["9f2c1b7d3e4a5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"], ignoreCase=true)

// Falcon: processes started from files read whole in the directory (MD5HashData)
#event_simpleName=ProcessRollup2
| in(field=MD5HashData, values=["0a1b2c3d4e5f60718293a4b5c6d7e8f9"], ignoreCase=true)

// Next-Gen SIEM: third party events to addresses found in the directory
in(field=destination.ip, values=["198.51.100.23", "203.0.113.9", "2001:db8::7"], ignoreCase=true)

// Next-Gen SIEM: third party DNS events for domains found in the directory
in(field=dns.question.name, values=["c2.evil-update.top", "cdn.panel-gate.xyz", "panel-gate.xyz", "*.c2.evil-update.top", "*.cdn.panel-gate.xyz", "*.panel-gate.xyz"], ignoreCase=true)

// Next-Gen SIEM: third party web events for URLs found in the directory
in(field=url.original, values=["*c2.evil-update.top/gate.php?id=1&k=**", "*panel-gate.xyz/files/*", "*raw.githubusercontent.com/someone/tools/main/x.ps1*"])
