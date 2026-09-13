# Security

## Reporting a problem

Open a GitHub issue for anything that is not itself sensitive. For a report that
should not be public, use GitHub's private vulnerability reporting on this
repository.

Two classes of bug matter more than the rest here, because they would make the
tool break its own promises:

1. **A way to make DirSift request a URL that was not linked from a parsed
   listing.** The tool guesses no paths; anything that gets around that is a
   real bug.
2. **A way to make DirSift leave its scope** — another host, a scheme downgrade,
   a climb above the root, a redirect that escapes the check.

Also worth reporting: anything that sends credentials, anything that writes to a
target, and any path where an indicator reaches output without being defanged.

## Scope of the tool

DirSift reads directory indexes that a server publishes and the files they list.
It sends only GET, holds no credentials, guesses no paths and writes nothing.
Those limits are enforced in `src/dirsift/fetcher.py` and covered by
`tests/test_rules.py`.

## Handling what comes back

Scan targets are hostile by assumption. The safe defaults DirSift uses, and the
ones it cannot enforce for you:

- File bodies are streamed and cut at a ceiling. DirSift never downloads a full
  binary and never executes anything.
- Nothing fetched is written to disk except inside the saved run JSON, as text.
- Filenames from a target are hostile input. DirSift does not use them to build
  local paths. If you save samples yourself, name them by hash, not by the name
  the operator chose.
- A saved run contains raw file contents. Treat a run JSON as untrusted data:
  the file previews in the UI are shown unmodified on purpose, because the
  contents are the evidence.
- Analysis of an actual sample belongs in an isolated VM with a snapshot and no
  route to your host. This tool is not a sandbox and the machine you run it on is
  not one either.

## Secrets

API keys are not needed: DirSift talks to no third-party service. If you add an
integration, read it from the environment, never log the config object, and keep
`.env` in `.gitignore` where it already is.
