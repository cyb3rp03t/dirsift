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

![A scan, the triage page it produces, a file read with its indicators marked, and two files turned into a rule](docs/demo.gif)

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
  artefact with five builds. Gaps stay visible: a jump from 4 to 6 means a build
  was pulled.
- **Guesses the entry point.** The file that names the other files, contains
  command-shaped strings and sits at the top of the tree is ranked first, with
  the reasons shown. It is a candidate, not a verdict.
- **Extracts indicators.** Addresses, URLs, domains, credential shapes, mutexes,
  registry keys and paths, each with the line it came from, deduped across
  defanged and live spellings, and defanged on the way out.
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
- **Writes the page.** A markdown triage report, plus a scaffold for the writeup
  that is left empty on purpose.

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
- **Slow on purpose.** One request per second by default, `Retry-After` honoured.
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

## Use

```bash
# triage a directory and write the report
dirsift scan http://203.0.113.10:8080/files/ -o triage.md --json run.json

# slower, deeper, quiet
dirsift scan http://203.0.113.10:8080/files/ --depth 4 --delay 3 -q

# through a proxy, because the target does not need your home address
dirsift scan http://203.0.113.10:8080/files/ --proxy socks5://127.0.0.1:9050

# re-render a saved run, offline, without touching the target again
dirsift report run.json -o triage.md

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

# hunts and candidate block lists: Sigma, Splunk, KQL, plain lists, CSV, STIX, YARA
dirsift detections run.json --list
dirsift detections run.json --target sigma -o hunts/
dirsift detections run.json --target all --tlp GREEN -o hunts.zip

# ask a public scanner about one digest, which is the only call that leaves
dirsift check 13565af72d91125920826dd15db83bd6e48aecc1a466b9a639a6780eaf037342

# which network an address belongs to, answered from disk
dirsift net 203.0.113.24

# the local triage UI
dirsift web
```

Scanning is separate from analysing on purpose. `--json` saves everything the
walk saw; `report` and `iocs` work from that file with no network at all. Sharpen
a rule, re-run the analysis, leave the target alone.

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

`detections` writes the same indicators in the shapes other tools read: a Sigma
rule collection (firewall, DNS, proxy and process creation log sources), Splunk
searches over the CIM data models, KQL for Microsoft Defender XDR and Sentinel,
plain one value per line block lists (IPv4, IPv6, domain, URL, SHA256) for
firewall external lists and threat feeds, a CSV for SOAR and TIP imports, the
STIX bundle and YARA. Every file says which log source it assumes, carries the
TLP label you pick (AMBER unless told otherwise) and is a file only: nothing is
sent to any product.

One filter runs before every format, and the files and the console count what it
left out and why: private, reserved, multicast and documentation addresses,
reserved names, protocol strings such as SSH algorithm names, public resolvers,
the hash of an empty file. A host many people share, such as GitHub or an S3
bucket, enters as a full URL only, never as a host to block. The scanned server
itself is labelled as the target. Wallets, mutexes and paths stay in YARA only.
A secret DirSift recognises (a key block, a cloud or chat token, a value assigned
to a name such as `password` or `aws_secret_access_key`) enters no file at all,
YARA included, and the indicator list, the report and the run page name it by
kind, length and the start of its sha256 instead of quoting it. A secret it does
not recognise is text like any other.

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


`dirsift web` serves a local page on `127.0.0.1:8000`. The run page leads with
the target, the address it answered from and the numbers that decide whether to
keep going, then the ranked entry points, the inventory, the indicators with
their networks, and the listing beside a preview panel, so picking a file never
loses the list.

The preview panel is where the reading happens:

- both hashes with a copy button, and how much of the file was actually read
- a warning when the magic bytes disagree with the extension
- the contents, raw and escaped, with the run's indicators marked in place and
  the lines numbered
- the first bytes as hex, for anything binary
- the indicators that came out of this file, each with the network it belongs
  to, the files that name it, and the other versions in its family, with a
  compare button between two of them
- a check button that asks a public scanner about the hash, and an open link
  that hands the same hash to your browser instead, which costs no API key

Every note at the bottom of a run carries a small `i`. Open it and the status
code is written out: what it means, who probably produced it, and what is worth
changing before going back.

Tick files in the listing to build a YARA rule from them. `j` and `k` walk the
listing from the keyboard, and the file you opened stays in the address bar, so
a preview can be reloaded or handed to someone else.

Fonts and htmx are vendored into the package, so the console works on an
air-gapped analysis box. It never reaches out on its own: a scan starts when you
press the button, every view after that is served from the saved run, and the
hash check is the one thing that leaves, only when pressed.

The console answers only to its own address. A request whose `Host` is not
`127.0.0.1`, `localhost`, `[::1]` or the address given to `--host` is refused
before any route runs, so a page that rebinds its own name to your loopback
cannot read runs or reports. Every request that changes something (starting a
scan, a hash check, saving an assessment, building a rule) must also come from
the console's own pages: a browser sends `Origin` (or `Referer`) with a form
post, and one naming another site is refused before a scan starts, a hash
leaves the machine or a file is written. A request with neither header, such as
your own `curl` on this machine, is accepted, because a browser cannot send a
cross-site post without them. Forms work with JavaScript turned off.

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
uv run pytest          # 276 tests
uv run ruff check .
```

Every push runs the suite on Windows and Linux, against Python 3.11 and 3.13.
That matrix is not decoration: the failures it catches are the ones that never
appear on the machine the code was written on. A console that cannot encode an
attacker's filename, a path separator, a line ending off an IIS box.

The tests that matter most are in `tests/test_rules.py`: they stand up a local
server and assert that only GET is ever sent, that a 401 ends the walk, that no
path is invented, and that the delay cannot be dialled to zero.

## Disclaimer

For research and defensive work. You are responsible for what you point it at:
the law about accessing someone else's server varies by country and is not
settled, and an open directory is not a general licence. If you are not sure
whether you are allowed to look at something, you are not sure.

Samples belong in a VM, never in a repository. `.gitignore` reflects that from
the first commit.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
