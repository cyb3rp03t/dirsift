# The demo video and the animation in the README

`demo.mp4` walks through DirSift one part at a time, each behind a short title
card: a scan from the terminal, the same scan in the console, the case file
(identity, likely drivers and the names graph), the inventory and the preview
window stepped with j and k, the indicators, a YARA rule from two picked files,
the rule pack (every family and every one of its formats, each with its preview
and a caption naming it), the report window (PDF or Markdown, and the TLP
label), and the offline commands `dirsift detections`, `dirsift stix` and
`dirsift report`. It runs about three and a half minutes at 1440 by 900 and
stays under GitHub's 10 MB upload limit.

`demo.gif` is about twenty seconds cut from the same recording for the top of
the README: the scan starting, the drivers, the preview stepping through files,
a YARA rule being written, a rule pack, and the report window.

Everything in both is real output against a harmless demo directory, and
nothing in either points at anyone's server.

## The demo target

`make-demo-target.py` builds a fake open directory in the system temporary
folder: a staging script, a PowerShell loader, a config with fake keys, a few
executables that are only magic bytes, a panel, a log. Every address in it is a
documentation range (RFC 5737, RFC 2606), so the network column stays empty
even on a machine that has the address table: those ranges are announced by
nobody.

## Rebuilding both

You need `uv`, an ffmpeg build with libx264, and a Playwright Chromium:

    uv run --with playwright playwright install chromium

Then, from the repository root:

    uv run --with playwright python docs/record-demo.py

or, with an ffmpeg that is not on the path:

    uv run --with playwright python docs/record-demo.py --ffmpeg /path/to/ffmpeg
    FFMPEG=/path/to/ffmpeg scripts/record-demo.sh

That one command does all of it:

1. Builds the demo target and serves it on `127.0.0.1:8806`.
2. Starts a console on `127.0.0.1:8801` against a new, empty runs folder in a
   temporary directory, so the dashboard shows only the demo run and the real
   `runs/` is never read or written.
3. Runs the terminal commands for real and keeps each line with the time it
   arrived. A page in `demo-assets/stage.html` plays them back at that pace,
   typed one key at a time.
4. Drives the console in Chromium and captures what it paints with the DevTools
   screencast. A Playwright video would compress the text until it blurs.
5. Renders the title cards from `demo-assets/card.html` in the console's font
   and colours, read from `dirsift.css`, with the Sift Mark from
   `dirsift-lockup-dark.svg`.
6. Cuts, joins and encodes with ffmpeg: H.264, 30 frames a second, about eight
   megabytes. Any ffmpeg with libx264 works; the one bundled with the
   `imageio-ffmpeg` package does. The scan waiting on the target plays a little faster than real
   time; nothing else is sped up.
7. Cuts the short animation from the same frames and hands them to
   `build-demo-gif.py`.

Pick other ports with `--console-port` and `--target-port`, and keep the frames
and clips for a look with `--work <folder>`.

## Changing what it shows

The order of the parts, the title card texts and the clicks are all in
`record-demo.py`: `CARDS` holds the cards, `console_take` the console part,
`SHOWCASE` the rule pack families in the order they are shown, and the two
`terminal_take` calls the commands. The rule pack caption exists only in the
recording; the console itself has none. The moments in the animation
are the `gif:` marks, each with how many seconds it keeps.

The terminal page uses a system monospace face (Cascadia Mono on Windows,
DejaVu Sans Mono on Linux), because the banner is drawn in box and block
glyphs that the console's embedded mono subset does not carry.

## The animation on its own

`build-demo-gif.py` turns a folder of frames into a GIF. It drops frames
identical to the one before and holds the previous one longer instead, which is
what keeps a mostly still page small, and it caps a hold at 1200 milliseconds
so a quiet moment does not read as a freeze:

    uv run --with pillow python docs/build-demo-gif.py frames docs/demo.gif 125 96

The two numbers are the milliseconds each frame is held and the palette size.
Keep the result under about five megabytes, which is what a README can carry
without becoming unpleasant to open.

## On GitHub

GitHub shows a player in a README only for a video uploaded through its web
editor, which gives it a `user-attachments` address. `demo.mp4` stays in the
repository as the source of that upload and for anyone reading the docs
offline.
