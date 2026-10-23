

https://github.com/user-attachments/assets/0bec1394-7f9b-4e90-b660-cc4885a3493d

<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/dirsift-lockup-dark.svg">
    <img src="docs/dirsift-lockup-light.svg" alt="DirSift" width="324" height="88">
  </picture>
</h1>

[![CI](https://github.com/cyb3rp03t/dirsift/actions/workflows/ci.yml/badge.svg)](https://github.com/cyb3rp03t/dirsift/actions/workflows/ci.yml)

**Triage an open directory: walk it, classify what is there, find the file that
drives the rest, and write the notes.**

You find an open directory. Forty files, half of them named like a build number,
a batch file somewhere, and no way to know what matters without opening every
one of them. DirSift does the mechanical part of that first pass and hands you a
markdown page you can argue with.

It does not decide anything for you. It collects.

```
██████╗  ██╗ ██████╗  ███████╗ ██╗ ███████╗ ████████╗
██╔══██╗ ██║ ██╔══██╗ ██╔════╝ ██║ ██╔════╝ ╚══██╔══╝
██║  ██║ ██║ ██████╔╝ ███████╗ ██║ █████╗      ██║
██║  ██║ ██║ ██╔══██╗ ╚════██║ ██║ ██╔══╝      ██║
██████╔╝ ██║ ██║  ██║ ███████║ ██║ ██║         ██║
╚═════╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚═╝ ╚═╝         ╚═╝
 s o m e o n e   l e f t   t h e   l i g h t s   o n
                   by cyb3rp03t
```

![A scan, the case file it produces, a file opened in the preview window, a rule pack, and the report window](docs/demo.gif)

**[Watch the full walkthrough](docs/demo.mp4)** (MP4). In order:

1. A scan started from the terminal
2. Progress while the walk runs
3. The case file: identity and likely drivers
4. The inventory and the preview window
5. Indicators
6. YARA from the files you pick
7. Rule packs: every family and every format, from SIEM hunts to IDS and DNS
8. The report window: PDF or Markdown
9. The same work from the command line

## Where it earns its keep: C2 servers

DirSift does its best work on attacker infrastructure: command-and-control
servers and the staging hosts beside them. Those boxes are stood up in a hurry
and left listing, and an open index on one usually holds the whole kit at once:
the loader, a run of builds, the config, and the script that ties them together.

That is the shape every part of DirSift is built for. The build run collapses
into one family with its gaps showing, the script that launches the rest is
ranked first, the callback addresses and domains come out of the files with the
line they sat on, each address is placed on its hosting network, and the files
you tick become YARA rules keyed to what they carried. One pass over a live C2
directory gives you the infrastructure to pivot on and the rules to hunt the
next build with, without ever running a sample.

## What it does

- **Walks the index.** Apache, nginx, IIS, Python `http.server`, Caddy, lighttpd,
  h5ai and JSON autoindex, breadth-first, bounded on depth, entries, requests and
  bytes.
- **Classifies by magic bytes, not by name.** It reads the first few kilobytes of
  each file, so `invoice.pdf` that starts with `MZ` shows up as the type mismatch
  it is. That row is usually the reason the directory was worth looking at.
- **Collapses version families.** `secrun2.exe` through `secrun6.exe` is one
  artifact with five builds. Gaps stay visible: a jump from 4 to 6 means a build
  was pulled.
- **Guesses the entry point.** The file that names the other files, contains
  command-shaped strings and sits at the top of the tree is ranked first, with
  the reasons shown. It is a candidate, not a verdict.
- **Guesses what the box is for.** Distribution server, panel, data drop,
  phishing kit or toolkit, each as a candidate with a score, the reasons and the
  files behind it, from the names and kinds it already has.
- **Extracts indicators.** Addresses, URLs, domains, credential shapes, mutexes,
  registry keys and paths, each with the line it came from, deduped across
  defanged and live spellings, and defanged on the way out. Each one carries a
  confidence from 0 to 100 that it is a live part of the kit, with the reasons.
- **Names secrets without quoting them.** A key block, a cloud or chat token, a
  value assigned to a name such as `password`, a login inside a link
  (`ftp://user:pass@host`) or one written bare (`user:pass@host`) is shown by its
  kind, its fixed opening (a PEM `BEGIN` line, `AKIA`, the link's host), its
  length and the start of its sha256. Two runs holding the same secret can be
  matched; neither one repeats it.
- **Hashes what it read whole.** sha256 and md5 for every file that fitted under
  the peek ceiling, in the listing, in the report and in `hashes.txt`. A file cut
  at the ceiling gets no hash and says so, because half a file hashes to nothing
  anyone can look up.
- **Asks about a hash, when you ask it to.** One button, one file: the digest
  goes to VirusTotal and comes back as a score like `6/64`. The sample is never
  uploaded and nothing is sent until you press it.
- **Writes YARA rules from what it read.** Tick the files, get one rule each,
  keyed to the indicators that file carried rather than to its digest. The hash
  stays in meta as identity: a hash matches one build, the address inside it
  usually survives the next one.
- **Writes detections for the tools you run.** **Twenty five outputs** from one
  saved run: **YARA**, a **STIX 2.1** bundle, a **MISP** event, a defanged
  **indicator list**, the **hash list**, **block lists** for IPv4, IPv6,
  domains, URLs and SHA256, a **Sigma** rule collection, **Splunk SPL**, **KQL**
  for Microsoft Defender XDR and Sentinel, **Elastic ES|QL** and detection
  rules, **Google SecOps YARA-L**, **IBM QRadar AQL** and reference sets,
  **CrowdStrike LogScale CQL**, **Suricata** rules, a **DNS response policy
  zone**, and a **CSV** for SOAR and TIP imports. Every one is a file;
  **nothing is sent to any product.**
- **Says what went wrong, in words.** A run's notes carry the status the server
  gave and a sentence about what it usually means: whether the branch was
  dropped on purpose, whether to slow down, and whether the answer came from
  the target at all. Antivirus software answers some requests itself, and a run
  that never left your machine should say so rather than blaming the host.
- **Places the addresses, offline.** Every IP it found, and the address the
  target itself resolved to, gets an AS number, the network's name and a
  country, read from a table on your disk. No lookup service is asked, because
  asking one tells a stranger what you are looking at. Optional: without the
  table the scan is unchanged.
- **Writes the searches for its siblings.** The title, the Server header, the
  port, the distinctive file names and the network become Shodan and FOFA
  queries for the other hosts built from the same kit. It writes them and runs
  none of them.
- **Hands it to a platform.** A saved run exports as a STIX 2.1 bundle that
  OpenCTI and MISP import as it is: the infrastructure, the files read whole, the
  indicators and where each came from, with no verdict attached.
- **Writes the report.** Markdown or PDF, from the console or from
  `dirsift report`, with a TLP label and an analyst assessment kept apart from
  what was observed. Every value in it is defanged.
- **Lays the run out as a case file.** A local console that reads a run in six
  numbered parts, opens any file in a preview window and walks the inventory
  from the keyboard.

## Rules of engagement

DirSift points at infrastructure that belongs to someone else. The limits are in
the code rather than in this file, and there are tests that fail if they break:

- **GET and HEAD only.** No other method is reachable from the fetcher.
- **No path guessing.** Every URL requested was linked from a listing DirSift
  already parsed. There is no wordlist and no `/admin` probe. Reading what a
  server volunteers is a different act from discovering what it does not.
- **No credentials, ever.** A 401 ends that branch of the walk.
- **Stay under the root.** Off-host links, scheme downgrades and parent links are
  recorded and not followed.
- **Slow on purpose.** One request per second by default, `Retry-After` honored.
  The delay can be raised but not dropped to zero.
- **Bounded reads.** File bodies are streamed and cut at a ceiling. DirSift wants
  the first bytes for a magic check, not the payload.
- **Nothing leaves unless you send it.** The scan itself talks to the target and
  to nothing else: no lookups, no enrichment, no submissions. The single
  exception is the hash check, which is a button you press for one file at a
  time, sends a digest and never a sample, and does nothing at all without an
  API key. Enrichment leaks what you are looking at, so it stays a decision you
  make rather than a default.

The line this draws is the practical one from the Harvard Cyberlaw Clinic's
researcher guidance: read what is served, take nothing that needs a credential,
guess no paths, bypass no controls, write nothing. Downloading a file an open
directory lists is not the same act as brute-forcing directory names, and only
one of them is the category researchers get sued over. This is a tool for the
first, and it cannot be configured into the second.

## Install

Needs Python 3.11 or newer. With [uv](https://github.com/astral-sh/uv):

```bash
git clone https://github.com/cyb3rp03t/dirsift
cd dirsift
uv sync
uv run dirsift --help
```

Or with pip:

```bash
pip install -e .
dirsift --help
```

The PDF report is drawn with ReportLab, and its fonts ship inside the package,
so nothing else needs installing.

## Use

```bash
# triage a directory, save the run, write the report
dirsift scan http://203.0.113.10:8080/files/ -o triage.md --json run.json

# slower, deeper, quiet
dirsift scan http://203.0.113.10:8080/files/ --depth 4 --delay 3 -q

# through a proxy, because the target does not need your home address
dirsift scan http://203.0.113.10:8080/files/ --proxy socks5://127.0.0.1:9050

# the report from a saved run, offline: the extension picks the format
dirsift report run.json -o report.pdf
dirsift report run.json -o report.md

# a TLP label, the analyst named on it, and an assessment file
dirsift report run.json -o report.pdf --tlp GREEN --author "Analyst Name"
dirsift report run.json -o report.pdf --assessment notes/run.assessment.json

# what changed on the host since the last visit, from two saved runs
dirsift diff old.json new.json -o changes.md

# just the indicators, for piping
dirsift iocs run.json --type ipv4

# search queries for hosts built from the same kit, written and not run
dirsift pivots run.json -o pivots.md

# only the narrowest Shodan queries, one per line, for piping
dirsift pivots run.json -e shodan -s narrow --plain

# sha256, md5 and path for the files read whole
dirsift hashes run.json

# YARA rules from that run, keyed to the indicators each file carried
dirsift rules run.json --out hunt.yar
dirsift rules run.json --name install.bat

# the run as a STIX 2.1 bundle for a platform, written to a file and nowhere else
dirsift stix run.json -o run.stix.json

# hunts and block lists: list the targets, write one, or write them all
dirsift detections run.json --list
dirsift detections run.json --target sigma -o hunts/
dirsift detections run.json --target blocklist-ipv4 -o lists/
dirsift detections run.json --target all --tlp GREEN -o hunts.zip

# ask a public scanner about one digest, which is the only call that leaves
dirsift check 13565af72d91125920826dd15db83bd6e48aecc1a466b9a639a6780eaf037342

# which network an address belongs to, answered from disk
dirsift net 203.0.113.24

# the local console, on 127.0.0.1:8000
dirsift web
```

Scanning is separate from analyzing on purpose. `--json` saves everything the
walk saw; `report`, `iocs`, `hashes`, `rules`, `stix` and `detections` work from
that file with no network at all. Sharpen a rule, re-run the analysis, leave
the target alone.

### The console

`dirsift web` serves a local page on `127.0.0.1:8000`. A scan started there
shows its progress while the walk runs (listings read, files opened, the stage
it is in) and opens the finished run as a case file. The page polls rather than
holding a connection, so closing it does not stop the scan.

The case file reads top to bottom in six numbered parts, with a band at the top
that jumps between them:

1. **Identity.** Who served this: the address it answered from, its network and
   country, the server and the index type, and the counts that decide whether to
   keep going.
2. **Drivers.** The ranked entry point candidates, each joined to the files it
   names, with the reasons for its rank.
3. **Inventory.** Every file grouped by what it turned out to be, executables
   first, with the version families below.
4. **Indicators.** What came out of the files, filterable by kind, each with its
   network and the file it came from.
5. **Detections.** YARA for the files you tick, and the rule pack: every
   detection target, previewed defanged, with copy and download giving the live
   file.
6. **Run settings.** The options the walk ran with, and its notes and errors.

Any file name opens the preview window over the page. It holds:

- both hashes with a copy button, and how much of the file was actually read
- a warning when the magic bytes disagree with the extension
- the contents, escaped, with the run's indicators marked in place and the
  lines numbered
- the first bytes as hex, for anything binary
- the indicators that came out of this file, each with the network it belongs
  to, the files that name it, and the other versions in its family, with a
  compare button between two of them
- a check button that asks a public scanner about the hash, and an open link
  that hands the same hash to your browser instead, which costs no API key

`j` and `k` step to the next and previous file without closing the window, and
`Escape` closes it. The file you opened stays in the address bar, so a preview
can be reloaded or handed to someone else.

File contents in the preview are shown as the file had them, because they are
the evidence. Everything else on the page is defanged: the target, the
indicators, the context lines. A recognized secret is named by kind, length and
digest there too, never quoted.

Every note at the bottom of a run carries a small `i`. Open it and the status
code is written out: what it means, who probably produced it, and what is worth
changing before going back.

Fonts and htmx are vendored into the package, so the console works on an
air-gapped analysis box. It never reaches out on its own: a scan starts when you
press the button, every view after that is served from the saved run, and the
hash check is the one thing that leaves, only when pressed. Without JavaScript
the page still works: the case file is one long page, the preview and the
report sit at its end, and every form is a plain submit.

### Console security

The console answers only to its own address. A request whose `Host` is not
`127.0.0.1`, `localhost`, `[::1]` or the address given to `--host` is refused
before any route runs, so a page that rebinds its own name to your loopback
cannot read runs or reports.

Every request that changes something (starting a scan, a hash check, saving an
assessment, building a rule) is accepted only from the console's own pages. A
browser sends `Origin` (or `Referer`) with a form post, and one naming another
site is refused before a scan starts, a hash leaves the machine or a file is
written. A request with neither header, such as your own `curl` on this
machine, is accepted, because a browser cannot send a cross-site post without
them.

Keep it on a loopback address. The default bind is `127.0.0.1`, and the console
has no login: `--host` exists for a lab network you control, not for exposing
it. To reach it from another machine, forward the port over SSH rather than
binding it wide.

### Reports

A report is built from a saved run, so writing one touches nothing on the
network. In the console the Report button opens the report window: pick PDF or
Markdown, pick a TLP label for this download, then download it or copy it as
text without the logo for a ticket or a chat. From the command line,
`dirsift report RUN -o FILE` picks the format by the extension, and without
`-o` prints Markdown.

The report has twelve numbered sections (executive summary, key facts,
analyst assessment, limits and alternatives, hosting and exposure, directory
contents, notable files and entry point candidates, indicators, hashes and
VirusTotal, detections and pivots, recommendations, and the method with its
rules of engagement) and three appendices: the full listing, all indicators
and a change log. Each
section is marked by what it holds: what was observed, what was derived from
it, the analyst's judgment, or the record. Every value is defanged.

**TLP.** `CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT` or `RED`. A run carries the
label saved with its assessment, and AMBER when none is saved. A looser label
picked for one download applies to that download only, with a warning, and does
not change the saved one.

**Analyst assessment.** The judgment is yours and is kept apart from the
evidence. The console saves it beside the run, in `runs/assessments/` under the
run's file name: author, TLP, assessment, confidence, priority, status, bottom
line, rationale, attribution, how the directory was found, and a status with a
reason for each alternative explanation. Until it is filled in, the report says
Not assessed and lists the open fields. A save made against an older copy is
refused rather than overwriting a newer one. On the command line the report
reads `assessments/<run file name>` beside the run, or the file given to
`--assessment`. `--author` names the analyst for that one report and is not
saved anywhere.

The PDF is a closed document: no links, no scripts, no forms, no embedded files.
The same run and assessment give the same bytes every time.

### What kind of box is this

An attacker's host does one of a few jobs, and the next step depends on which.
The report (section 2.1) and the terminal summary lead with a guess:

| Role | What it means |
|---|---|
| `distribution` | Hands out the payload: a loader, a run of builds, the script that ties them together |
| `panel` | The operator's panel or gate: login, gate, config and the folders a panel keeps |
| `drop` | Where stolen data lands: stealer logs, folders named after victims, dumps |
| `phishing` | A phishing kit, or what it wrote: a cloned page, its form handler, its results |
| `toolkit` | What the operator carries: tunnels, credential dumpers, scanners |

Each role gets a score, the reasons that set it and the files behind them. With
no role at 50 or above the answer is unclear, and two close roles are reported
as mixed. It is worked out from file and folder names, the kinds the classifier
gave them and the indicators already extracted. No request is made for it and
no file is read again. The STIX export names the same roles as infrastructure
types.

Tool names are cheap. A file called `mimikatz.exe` is a file someone named
that; check the bytes before believing it.

When a directory reads like a drop, the report opens with a warning: it may
hold other people's stolen data. DirSift read only the head of each file and
changes nothing about what it does, but decide how to handle that data under
your organisation's rules before pulling more, and treat the saved run JSON
with the same care.

### How sure is it

Sixty indicators out of one directory are rarely sixty pieces of
infrastructure. Some are the kit's own callbacks; others are an address in a
comment, a resolver pinged to test the line, a domain someone wrote down
defanged. Every indicator gets a confidence from 0 to 100 that it is a live,
pivotable part of this kit. It is not a judgement of whether it is malicious:
DirSift weighs how the indicator sits in the files, and every point comes with
its reason.

| Observation | Points |
|---|---:|
| Where every indicator starts | 50 |
| Each further file that names it, up to +20 | +10 |
| Kept across two or more builds of one version family | +15 |
| In a config file or a script | +10 |
| Named by the likely entry point | +5 |
| Points back at the host being triaged | +10 |
| Only ever in comments | -15 |
| Written only defanged in the source | -25 |
| A private, CGNAT or link-local address | -20 |
| A public resolver such as 8.8.8.8 | -30 |
| Seen only in files cut at the peek ceiling | -5 |

75 and above is high, 50 to 74 medium, below that low. The report shows the
band and score beside every value in its most useful table, and on every line
of the appendix that lists all indicators, highest first, with the reasons
beside the low ones; the run file keeps them all. STIX indicators carry the
score as their confidence, and indicator pivots are ordered by it. `iocs` takes
a threshold, and without one its output is unchanged:

```bash
dirsift iocs run.json -c 75
```

### Revisiting a host

Staging hosts change between visits: builds are added, detected ones are pulled,
and now and then the whole box moves to another provider. `diff` puts two saved
runs side by side and leads with exactly that: a new network, a file whose type
changed, bytes that changed, builds that joined or left a family, indicators
that are new or gone.

A file missing from the second run is only called removed when the folder it sat
in was listed again. A shallower walk, a spent request budget or a refused
folder leaves it under "not seen" instead, and the options that differ between
the runs are printed beside it. A file cut at the peek ceiling has no hash, so
its row says what the listing claims and not what the bytes did.

### Taking it to a platform

`stix` turns a saved run into a STIX 2.1 bundle that OpenCTI and MISP import
without editing: one Infrastructure for the directory, its URL and address, a
File and a hash Indicator for every file read whole, and an Indicator for every
address, domain and URL lifted out of them, tied to the file it came from.

There is no Malware object and no verdict in it. DirSift collects; whether any
of this is hostile is decided on the platform, by whoever reads it there.

The STIX file in the rule pack is filtered like every other format: private and
reserved addresses, public resolvers, shared hosts and any value that carries
part of a secret are left out. `dirsift stix RUN` writes the whole run.

A platform matches live values, so the bundle carries them undefanged. That is
why it is only ever written to the file you name, never to the terminal.
Identifiers are deterministic: importing the same run twice adds nothing the
second time, and an address found in two runs lands on the same object.

### Hunts and block lists

`detections` writes the same indicators in the shapes other tools read. There
are twenty five targets, and `--list` shows what each one would carry for a
given run:

| Target | Output | For |
|---|---|---|
| `yara` | YARA rules | the files picked with `--pick`, or ticked in the console |
| `stix` | STIX 2.1 bundle | OpenCTI, MISP, Cortex XSOAR, Sentinel threat intelligence |
| `indicators` | defanged list | notes and chat |
| `hashes` | sha256, md5 and path | the files read whole |
| `blocklist-ipv4`, `blocklist-ipv6`, `blocklist-domain`, `blocklist-url`, `blocklist-sha256` | one value per line | Palo Alto EDL, Fortinet threat feeds, Check Point, Cisco, pfSense and OPNsense |
| `sigma` | Sigma rule collection | any SIEM through sigma-cli (firewall, DNS, proxy and process creation log sources) |
| `splunk` | SPL searches | Splunk Enterprise and Enterprise Security, over the CIM data models |
| `kql` | KQL queries | Microsoft Defender XDR advanced hunting and Microsoft Sentinel |
| `elastic-esql` | ES&#124;QL queries | Elastic Security hunting over ECS fields, one query per field family |
| `elastic-rules` | detection rules (NDJSON) | Elastic Security rule import: KQL custom query rules, imported disabled |
| `secops-yaral` | YARA-L 2.0 rules | Google SecOps (Chronicle), over UDM fields |
| `qradar-aql` | AQL searches | IBM QRadar Advanced Search over events, flows and payloads |
| `qradar-set-ip`, `qradar-set-domain`, `qradar-set-url`, `qradar-set-hash` | reference set files | IBM QRadar reference sets, loaded with `ReferenceDataUtil.sh load` |
| `logscale-cql` | CQL queries | CrowdStrike Falcon LogScale and Next-Gen SIEM |
| `suricata` | IDS rules | Suricata (DNS, TLS SNI, HTTP host and URL, IP); the IP rules also read in Snort 3 |
| `rpz` | response policy zone | BIND, Unbound, Knot Resolver and PowerDNS Recursor (NXDOMAIN for each domain and its subdomains) |
| `misp` | MISP event (core format) | MISP event import, distribution limited to your organisation |
| `csv` | CSV | SOAR and TIP list imports |

Every file says which log source it assumes, carries the TLP label you pick
(`CLEAR`, `GREEN`, `AMBER` or `RED`, AMBER unless told otherwise) and is a file
only: nothing is sent to any product. `--type` and `--source` narrow it to some
indicator types or one file, and `--profile` sets the comment style of the block
lists (`generic`, `paloalto` or `bare`).

Some languages have no documented way to write a character a value may hold:
a single quote in AQL, a value with both quote kinds in YARA-L, a comma in a
QRadar reference set, a character a zone file reads as syntax. Such a value is
left out of that one file, and the file says how many were. Suricata rules take
sids from the local range 1000000 to 1999999, derived from the indicator, so
the same indicator keeps its sid from run to run. The PDF and Markdown reports
list the formats by family (SIEM queries, rules and sharing, block lists,
network) rather than file by file.

One filter runs before every format, and the files and the console count what it
left out and why: private, reserved, multicast and documentation addresses,
reserved names, protocol strings such as SSH algorithm names, public resolvers,
the hash of an empty file. A host many people share, such as GitHub or an S3
bucket, enters as a full URL only, never as a host to block. The scanned server
itself is labeled as the target. Wallets, mutexes and paths stay in YARA only.
A secret DirSift recognizes (a key block, a cloud or chat token, a value assigned
to a name such as `password` or `aws_secret_access_key`, a login inside a link or
written bare as `user:pass@host`) enters no file at all, YARA included, and the
indicator list, the report and the run page name it by kind, length and the
start of its sha256 instead of quoting it. The host of a login stays an
indicator, and a link keeps its address with the login removed. When
`name:value@domain` reads as a mail field rather than a login (`mailto:`,
`sender:`, a header ending in `-To`, or a mailbox-like name such as
`noreply@`), the email is kept and nothing is hidden. A secret it does not
recognize is text like any other.

The files carry live values, so `-o` is required and nothing is printed. In the
console the preview is defanged; copy and download give the live file.

### Finding the siblings

An operator rarely runs one server. The next one is stood up from the same kit,
and it carries the same marks: the page title, the Server header, the port, the
file names, the provider. `pivots` writes those as queries for Shodan and FOFA,
ranked narrow, medium or broad, each with the reason it was ranked that way and
a link that opens it in the engine.

None of them is run. A query tells a stranger what you are looking at, so
pasting one is your call, the same way the hash check is. Shodan also wants a
logged-in account before it answers a filtered search.

The engines index the page at the root of each port and do not walk below it.
A listing found under `/files/` was never stored by them, so every query built
from it is marked and trusted a step less, and a guess at the root's own title
is added beside them. The syntax lives in one table in `pivots.py`, because the
engines change it; when a query stops matching, check that table first.

## Addresses and their networks

The hosting provider behind an address is the part that repeats between
campaigns. The address itself changes; AS14061 does not. DirSift will tell you
which network every address belongs to, but only from a table you already have,
never from a lookup service: a query is a disclosure, one address at a time, and
this tool does not make them.

Get the table once, from [iptoasn.com](https://iptoasn.com/), and put it where
DirSift looks:

```bash
mkdir -p ~/.dirsift
curl -L -o ~/.dirsift/ip2asn-combined.tsv.gz https://iptoasn.com/data/ip2asn-combined.tsv.gz
```

Or keep it anywhere and say so:

```bash
export DIRSIFT_ASN_DB=/srv/data/ip2asn-combined.tsv.gz
```

The gzip is read in place, so there is nothing to unpack. From then on the run
page, the report and the terminal show `AS13335 CLOUDFLARENET US` beside each
address, and the report names the file and its date: an announcement that
changed hands last month makes a stale table lie with confidence.

Without the table, nothing breaks. The addresses are simply not placed.

## Options that matter

| Option | Default | Why you would change it |
|---|---|---|
| `--depth` | 2 | Deep trees. Costs requests fast. |
| `--delay` | 1.0 | Raise it on a host you do not want to annoy. Floor is 0.2. |
| `--no-peek` | off | Map the tree without reading any file body. |
| `--peek-bytes` | 65536 | Lower for speed, raise for long scripts. |
| `--max-requests` | 600 | The hard stop. |
| `--proxy` | none | Route through Tor or a VPS. |
| `--allow-private` | off | Needed for loopback and RFC1918 targets. |

`DIRSIFT_ASN_DB` points at the address table, and `DIRSIFT_VT_API_KEY` holds the
VirusTotal key. Both are environment variables rather than flags, so neither
ends up in a command line that every process on the box can read.

## What it is not

Not a scanner, not a crawler, not a sandbox, not an enrichment pipeline. It reads
one directory that is already open and tells you what is in it. The network beside
an address comes from a file on your own disk, and the hash check only happens on
the file you press it for: neither one is a feed, and neither one runs by itself.

Pulling a sample and running it is a separate decision that belongs in an
isolated VM with a snapshot and no route to your host. DirSift never downloads a
full binary and never executes anything.

## Development

```bash
uv sync
uv run pytest -q       # 1300+ tests
uv run ruff check .
```

Every push runs the suite on Windows and Linux, against Python 3.11 and 3.13.
That matrix is not decoration: the failures it catches are the ones that never
appear on the machine the code was written on. A console that cannot encode an
attacker's filename, a path separator, a line ending off an IIS box.

The tests that matter most are in `tests/test_rules.py`: they stand up a local
server and assert that only GET is ever sent, that a 401 ends the walk, that no
path is invented, and that the delay cannot be dialed to zero. Next to them,
`tests/test_leak_oracle.py` builds a run full of secrets, logins in links and
bare logins, and checks every exit (each detection file, the zip, the Markdown
report, the console pages and the command line) for any piece of them, raw or
defanged.

## Disclaimer

For research and defensive work. You are responsible for what you point it at:
the law about accessing someone else's server varies by country and is not
settled, and an open directory is not a general license. If you are not sure
whether you are allowed to look at something, you are not sure.

Samples belong in a VM, never in a repository. `.gitignore` reflects that from
the first commit.

## License

Apache-2.0. See [LICENSE](LICENSE).
