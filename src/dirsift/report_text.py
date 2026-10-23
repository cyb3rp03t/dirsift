"""Every fixed sentence the report writes, in one place.

The report is built from rules, and the rules pick sentences from this
catalogue; nothing in the report is free text except what an analyst typed.
Keeping the sentences here lets one test read all of them for the words a
triage report must not use (a verdict or a guess written as if it were an
observation), and lets the console show the same TLP and scale definitions
the report prints.
"""

from __future__ import annotations

#: FIRST TLP 2.0 definitions, verbatim (first.org/tlp, section 3). Ordered from
#: least to most restrictive; the order is what the downgrade warning compares.
TLP_DEFINITIONS: dict[str, str] = {
    "CLEAR": "Recipients can spread this to the world, there is no limit on disclosure.",
    "GREEN": "Limited disclosure, recipients can spread this within their community.",
    "AMBER": "Limited disclosure, recipients can only spread this on a need-to-know basis "
    "within their organization and its clients.",
    "AMBER+STRICT": "TLP:AMBER+STRICT restricts sharing to the organization only.",
    "RED": "For the eyes and ears of individual recipients only, no further disclosure.",
}
TLP_ORDER: tuple[str, ...] = tuple(TLP_DEFINITIONS)
DEFAULT_TLP = "AMBER"

TLP_NOT_SET = "TLP not set; using TLP:AMBER"
TLP_DOWNGRADE = "TLP:{choice} is less restrictive than the saved TLP:{saved} for this run."
TLP_UNKNOWN = "Unknown TLP label. Use one of: CLEAR, GREEN, AMBER, AMBER+STRICT, RED."

#: The analyst's scales (template section 3.1), each value with its one line definition.
NOT_ASSESSED = "Not assessed"
NOT_ASSESSED_DEFINITION = "No one has looked yet. Not the same as Undetermined."
ASSESSMENT_DEFINITIONS: dict[str, str] = {
    "Malicious infrastructure": "the analyst concludes the server stages or runs tooling for "
    "misuse",
    "Suspicious": "signs of misuse, not enough for a conclusion",
    "Benign or research": "authorised testing or research, no sign of misuse",
    "Undetermined": "an analyst looked and could not decide",
}
CONFIDENCE_DEFINITIONS: dict[str, str] = {
    "High": "ICD 203 high confidence: the judgement rests on strong evidence",
    "Moderate": "ICD 203 moderate confidence: credible evidence, open to other readings",
    "Low": "ICD 203 low confidence: thin or fragmentary evidence",
}
PRIORITY_DEFINITIONS: dict[str, str] = {
    "High": "follow up first",
    "Medium": "follow up after the high priority work",
    "Low": "follow up when time allows",
    "Informational": "kept for the record, no follow-up asked",
}
STATUS_DEFINITIONS: dict[str, str] = {
    "Preliminary": "no analyst has signed off the assessment yet",
    "Final": "an analyst reviewed it; needs Author, Assessment and Bottom line, and "
    "Confidence unless the assessment is Undetermined",
}

#: ICD 203 probability terms, for the analyst's own text (template section 3.3).
ICD203_SCALE: tuple[tuple[str, str], ...] = (
    ("almost no chance", "1 to 5 %"),
    ("very unlikely", "5 to 20 %"),
    ("unlikely", "20 to 45 %"),
    ("roughly even chance", "45 to 55 %"),
    ("likely", "55 to 80 %"),
    ("very likely", "80 to 95 %"),
    ("almost certain", "95 to 99 %"),
)
ICD203_NOTE = (
    "Use these terms for probability in your own text. Do not combine a confidence level "
    "and a probability in one sentence."
)

#: The five readings an open directory is often mistaken for (section 4.2).
ALTERNATIVES: tuple[str, ...] = (
    "Red team or penetration test infrastructure",
    "Security researcher's lab or honeypot",
    "Legitimate server compromised by a third party",
    "Collection of someone else's public tools or proofs of concept",
    "Shared or resold hosting: other tenants on the same address",
)
NOT_RULED_OUT = "Not ruled out"
RULED_OUT = "Ruled out"

#: Reader labels shown beside each section.
LABELS = {"O": "Observed", "D": "Derived", "A": "Analyst", "R": "Record"}

DISTRIBUTION = (
    "Defanged throughout: [.] replaces dots, hxxp replaces http. Contains no file contents "
    "and no secret values."
)
AUTHOR_NOT_SET = "Not set. Add the analyst who reviewed this report before sharing it."
STATUS_PRELIMINARY = "Preliminary. The assessment is not signed off yet."
STATUS_FINAL = "Final, reviewed by {author}."
REVIEW_NOT_REVIEWED = "Generated, not reviewed"
REVIEW_BY = "Reviewed by {author}"
RUN_NOT_SAVED = "run not saved"
COVER_TLP_GUARANTEE = (
    "Every host, address and URL in this report is defanged; it contains no file contents "
    "and no secret values."
)
REPORT_KIND = "Open directory triage report"
TITLE = "Open directory triage: {target}"
COVER_TITLE = "Open directory triage"
COVER_KICKER = "Triage report · scanned {date}"
CONTINUED = "(continued)"

# Section 1
SUMMARY_LISTED = (
    "On {date} at {time} UTC, DirSift listed an open directory at {target} ({network}), "
    "served by {server}."
)
SUMMARY_NOT_LISTED = (
    "On {date} at {time} UTC, DirSift asked {target} ({network}) for a listing and got none."
)
SUMMARY_HELD = "The listing held {files} in {dirs}: {kinds}."
SUMMARY_HELD_EMPTY = "The listing held no files."
SUMMARY_NAMES = "The files named by the most entry point candidates are {names}."
SUMMARY_SIGNALS = "Signals worth a second look: {signals}."
SUMMARY_READ = (
    "DirSift read {read} files, hashed the {hashed} it read whole and extracted {iocs} "
    "indicator values."
)
SUMMARY_TOP = "The top entry point candidate, {name}, names {refs} in the directory."
SUMMARY_VT_ONE_NONE = "One VirusTotal hash lookup returned no record."
SUMMARY_VT_ONE_FOUND = "One VirusTotal hash lookup returned a record."
SUMMARY_VT_MANY = "{n} VirusTotal hash lookups: {parts}."
SUMMARY_LATER = "A later run on {date} could not list the root ({detail})."
SUMMARY_CLOSING = (
    "This summary states what DirSift observed. It makes no judgement of intent; see section 3."
)

# Section 2
FACTS_TOP = "{name}, {score} of 100, a candidate, not a conclusion"
FACTS_NO_SIZE = "Not advertised by the server. DirSift read {size} across {files} files."
FACTS_HASHED = (
    "{hashed} files read whole; {cut} cut at the {ceiling} ceiling; {unread} not read "
    "({detail}, see section 12)"
)
FACTS_INDICATORS = "{counts} (section 8 counts the units)"
FACTS_NO_INDICATORS = "none extracted"
FACTS_VT_NONE = "No lookup was made."
FACTS_VT_NO_RECORD = "no record"
FACTS_VT_RECORD = "{hits} of {total} engines reported a detection"
FACTS_PACKS_NOT_MADE = "{packs} not generated (no files picked)."
FACTS_PACKS_NONE = "none: no indicator belongs in a rule"
NOTE_NETWORK = (
    "Note 1: network from the offline table {table}, dated {stamp}, {when}. The country is the "
    "announcing network's registration, not the machine's location."
)
NOTE_NETWORK_NONE = (
    "Note 1: no offline network table was on this machine, so the address is not placed."
)
NETWORK_RECORDED = "recorded in the run at scan time"
NETWORK_PLACED_NOW = "placed when this report was generated"
NOTE_LATER = "Note 2: {runs}"
NOTE_LATER_RUN = "run {name} on {date} could not list the root ({detail})"
NOTE_NO_LATER = "Note 2: no later run of this target"
NOT_PLACED = "not placed"
NO_ERROR_RECORDED = "no error recorded"
NO_ANSWER_RECORDED = "no answer recorded"

# Section 3
ASSESSMENT_EMPTY = (
    "**Not assessed.** DirSift reports what it observed; the judgement here is an analyst's "
    "to make. Fill it in the console (Report, Assessment) or pass an assessment file to "
    "`dirsift report`."
)
ASSESSMENT_OPEN_FIELDS: tuple[str, ...] = (
    "Author", "Assessment", "Confidence", "Priority for follow-up", "Bottom line",
    "Rationale", "Attribution", "Found via", "ATT&CK techniques",
)
ASSESSMENT_NO_RATIONALE = "None given"
ASSESSMENT_NO_ATTRIBUTION = "None asserted"
ATTACK_NOT_MAPPED = (
    "Not mapped. DirSift does not map techniques; an analyst adds them with evidence."
)
ATTACK_VERSION_NOT_STATED = "version not stated"
AWAITING_ANALYST = "Awaiting analyst"
#: Printed in the PDF when analyst text holds characters its fonts cannot draw
#: (Arabic or Hebrew script, for example). Nothing is dropped without saying so.
GLYPHS_MISSING = (
    "Some characters in the analyst's text are outside the fonts this PDF carries "
    "(Arabic or Hebrew script, for example) and are shown as �. The Markdown "
    "report holds the full text."
)

# Section 4
LIMIT_EXECUTED = "That any file was executed, here or anywhere. DirSift ran nothing."
LIMIT_CUT = "the contents of {files} beyond their first {ceiling}"
LIMIT_UNREAD = "anything from {files} DirSift could not read ({detail}, see section 12)"
LIMIT_LOGS = (
    "What the {n} addresses found only in log files were to the server: visitors, targets or "
    "destinations. A log line does not say."
)
LIMIT_RESOLVED = (
    "That any extracted domain or URL was reachable or in use. None was resolved or requested."
)
LIMIT_SECRETS = (
    "That the masked secrets are valid. Their values were not tested and are not in this report."
)
LIMIT_OPERATOR = (
    "Who operates the server. The network in Key facts announces the address; it need not be "
    "the operator."
)
LIMIT_VT = "What the files do. {lookups} found {found}; absence of a record is not a verdict."
LIMIT_NO_VT = "What the files do. No file was looked up anywhere."
LIMIT_WINDOW = "What the directory held before {start} or after {end}."
ALTERNATIVES_LEAD = (
    "Common misreads of open directories. Each stays **Not ruled out** until an analyst rules "
    "it out with a reason."
)

# Section 5
FOUND_VIA_NOT_RECORDED = "not recorded. The analyst adds it in the console (Report, Assessment)."
SEEN_LISTED = "listed {files} files, {dirs} directories; {requests}"
SEEN_NOT_LISTED = "could not list the root ({detail}); {requests}"
FIRST_SEEN = (
    "First seen on the internet: not known to DirSift. Scanner history is outside the rules "
    "of engagement; an analyst may add it."
)

# Section 6
NOTHING_LISTED = "Nothing was listed."
NO_SIZES = "The server did not advertise sizes, so Read is what DirSift fetched, not the file size."
NO_FAMILIES = "None: no two files differ only by a version token."
FAMILY_GAP = "A gap in the numbers can mean a removed build or one that was never published."

# Section 7
CANDIDATES_LEAD = (
    "Ranked by how much each file looks like the one that runs the rest. Candidates, not "
    "conclusions."
)
NO_CANDIDATES = "No file reads like a driver for the others."
NO_SIGNALS = "None: no file met a rule for a second look."
NO_MISMATCHES = "Type mismatches: none. Every sniffed file's magic bytes agree with its extension."
SIGNAL_MISMATCH = "type mismatch: {note}"
SIGNAL_KEY = "key material location (contents not shown)"
SIGNAL_HOME = "home directory dot files"
SIGNAL_NAMES = "name on the configuration and credential names list"
SIGNAL_NOEXT = "executable with no extension"
SIGNAL_SAME = "identical SHA256: same content under {n} names"

# Section 8
INDICATORS_LEAD = (
    "Defanged. Extracted from file contents only; none was resolved, queried or submitted. "
    "Presence here is not proof of malicious use."
)
NO_INDICATORS = "Nothing extracted: the readable files held no indicators."
IPV4_UNITS = (
    "IPv4 is counted in values as found: {values} values, {distinct} distinct addresses, "
    "{ported} with a port. The rules in section 10 drop the port and the values listed there "
    "as left out, which leaves {kept} addresses."
)
MOST_USEFUL_NOTE = (
    "Pointing at the target first, then found in scripts and configuration, other text, logs; "
    "then found in more files. Values inside a file path, network base addresses, private, "
    "reserved and resolver addresses are left out here. At most 10 rows; Appendix B holds "
    "every value. Confidence is how sure the run is that the value is a live part of this "
    "kit, from 0 to 100 (high from 75, medium from 50); it says nothing about intent."
)
MOST_USEFUL_NONE = "None: every network indicator here is one of the kinds left out above."
NOTE_TARGET = "the target itself"
NOTE_PORT = "port {port}"
NOTE_BASE = "network base address"
NOTE_FILE_PATH = "inside a file path"
NOTE_SHARED = "shared hosting"
NOTE_PROTOCOL = "protocol identifier"
NOTE_FROM_LOGS = "from logs: role unknown"
NOTE_MASKED = "masked"
NOTE_B58 = "fails the Base58Check checksum"
NOTE_FRAGMENT = "part of a longer token"
CAT_FROM_LOGS = "from logs only, role unknown (visitor, target or destination)"
TYPE_IPV4_NOTE = "{distinct} distinct addresses; {ported} values carry a port"
TYPE_SHARED_NOTE = "{n} on shared hosting ({suffixes})"
TYPE_PATH_NOTE = "{n} inside a file path, not used as a host: {values}"
TYPE_PROTOCOL_NOTE = "{n} protocol identifiers ({domains}), not mailboxes"
TYPE_SECRET_NOTE = "values masked: type, length and a SHA256 fingerprint only"
NET_NOT_RESOLVED = "not resolved"
NET_NOT_IN_TABLE = "not in table"

# Section 9
HASHES_LEAD = (
    "{hashed} files were read whole and hashed: {distinct} distinct non-empty SHA256 values "
    "across {files} files{empty}. The full table, with MD5, is in Appendix A. A file cut at the "
    "read ceiling has no hash: half a file hashes to nothing anyone can look up."
)
HASHES_EMPTY = ", and the empty-file hash `{short}` for {files}"
HASHES_NONE = "No file was read whole."
HASHES_SAME = " Identical content under several names is listed in section 7."
VT_NOTE = (
    "Only the hash left this machine, and only because the analyst pressed the lookup button. "
    "No record means VirusTotal had not seen the file on that date; it is not evidence that the "
    "file is benign. {rest}"
)
VT_NONE = (
    "No lookup was made. Hashes leave this machine only when the analyst presses the lookup "
    "button."
)

# Section 10
DETECTIONS_LEAD = (
    "Candidate content for hunting, generated from the indicators after leaving out {total} "
    "values that do not belong in a rule ({reasons}). Review before deploying. Downloads carry "
    "live values; this report shows none."
)
DETECTIONS_LEAD_NOTHING_LEFT_OUT = (
    "Candidate content for hunting, generated from the indicators. Review before deploying. "
    "Downloads carry live values; this report shows none."
)
DETECTIONS_NONE = "None: no indicator here belongs in a rule."
SHARED_UNIT = "distinct host names from domains and URLs"
YARA_NOT_GENERATED = "not generated"
YARA_NO_PICK = "no files were picked; pick files in the console to write rules"
STRICT_WARNING = (
    "Detection downloads are marked TLP:AMBER at most; handle them as TLP:AMBER+STRICT."
)
PIVOTS_LEAD = (
    "**Not executed.** DirSift wrote {n} queries for internet search engines ({narrow} narrow, "
    "{medium} medium, {broad} broad) and ran none of them. A query tells the engine's operator "
    "what you are looking at, so running one is the analyst's decision. Shown: the first two of "
    "each strength. Values are defanged here; `dirsift pivots` prints them ready to paste."
)
PIVOTS_NONE = "None: nothing in this run gives a search engine a query to run."

# Section 11
RECOMMENDATIONS_LEAD = (
    "Generated from what was found; review them before sharing. These are operational "
    "suggestions, not legal advice: reporting duties and permitted actions depend on your "
    "jurisdiction and role."
)
REC_NETWORK = (
    "Check the network indicators against your allow lists, then add them to block or alert "
    "lists. Shared hosting addresses can serve unrelated sites."
)
REC_HASHES = (
    "Search endpoint and proxy telemetry for the {n} distinct non-empty SHA256 values and the "
    "file names in Appendix A over a look-back window that suits your retention."
)
REC_INCIDENT = "Handle any match under your incident response process."
REC_ROTATE = (
    "Rotate the credentials found in {files} if they belong to your organisation (values masked "
    "here; {n} found)."
)
REC_ABUSE = (
    "Report the host to the abuse contact of AS{asn} ({name}) and to a community feed such as "
    "URLhaus. Send hashes and defanged paths, never samples."
)
REC_RERUN = (
    "Re-run DirSift before acting on these indicators: Censys (2025) found half of open "
    "directories online for a day or less."
)
REC_LAST_FAILED = " The last run, on {date}, could not list the root ({detail})."
REC_LAST_GONE = " The last run, on {date}, found it no longer listing."

# Section 12
METHOD_ROWS: dict[str, str] = {
    "Methods": "GET and HEAD only",
    "Path guessing": "none: every URL requested appeared in a parsed listing",
    "Credentials": "none; a 401 or 407 ends that branch",
}
METHOD_SCOPE = "stayed under {root}; no host change, no scheme downgrade"
METHOD_PACE = "{delay} s between requests, timeout {timeout} s"
METHOD_BUDGETS = (
    "depth {depth}, {entries} entries, {requests} requests; used {used} requests, {bytes}"
)
METHOD_READS = (
    "first {peek} of each file; nothing executed, no binary kept, no samples retained"
)
METHOD_READS_NONE = "no file bodies read; nothing executed, no binary kept, no samples retained"
METHOD_OUTSIDE_VT = "{lookups}, made by the analyst. "
METHOD_OUTSIDE = "No other lookup, resolution or submission."
METHOD_NETWORK = "offline table {source}"
METHOD_NETWORK_NONE = "no offline network table on this machine"
NOT_RECORDED = "not recorded"
NO_NOTES = "None: every listed file answered."
NO_EXPLANATION = "No explanation is on file for this note."

# Appendices
NO_MODIFIED = "The server did not advertise modification times, so that column is left out."
LISTING_CUT = "cut at the ceiling"
LISTING_UNREAD = "not read"
APPENDIX_B_LEAD = (
    "Defanged; secrets and masked wallet-shaped values by type, length and SHA256 fingerprint. "
    "Each line gives the value, its confidence (how sure the run is that it is a live part of "
    "this kit, 0 to 100; it says nothing about intent) and the files it came from. Highest "
    "confidence first, then by value; a low score carries its reasons."
)
CHANGELOG_GENERATED = "Generated from run {name}."
CHANGELOG_GENERATED_UNSAVED = "Generated from a scan that was not saved."
#: The generation row once an analyst has edited: it comes last, as the
#: version the edits reached, so the log reads in time order.
CHANGELOG_GENERATED_AS = "Generated as version {version} from run {name}."
CHANGELOG_GENERATED_AS_UNSAVED = "Generated as version {version} from a scan that was not saved."
CHANGELOG_CHANGED = "Changed: {fields}."
CHANGELOG_SHA_DIFFERS = (
    "Run file SHA256 differs from the one recorded when the assessment was saved."
)

#: Words a generated sentence must not use: each one is a verdict or a guess
#: dressed as an observation. Checked against this module and rendered reports.
FORBIDDEN_WORDS: tuple[str, ...] = (
    "malicious", "attacker", "botnet", "campaign", "likely", "unlikely", "probably", "usually",
    "appears", "apparently", "possibly", "presumably", "seems", "suggests", "typically", "often",
)
#: The only phrases allowed to carry one of those words.
FORBIDDEN_ALLOWED: tuple[str, ...] = ("not proof of malicious use", "Malicious infrastructure")
