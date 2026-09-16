# The animation in the README

`demo.gif` is a real session: a scan of a local demo directory, the triage page
it produces, one file opened and read, and two files turned into a YARA rule.
Nothing in it points at anyone's server.

To rebuild it after the UI changes:

1. Build the demo target and serve it.

       python docs/make-demo-target.py
       python -m http.server 8765 --bind 127.0.0.1 --directory <the folder it printed>

2. Start the console, and make sure the dashboard is not carrying real runs you
   would rather not publish. Move them out of `runs/` for the recording.

       uv run dirsift web

3. Record, then turn the recording into a GIF.

       npm i playwright
       node docs/record-demo.mjs http://127.0.0.1:8000 http://127.0.0.1:8765/
       ffmpeg -i docs/demo-recording/<recording>.webm -r 5 -s 700x438 frames/f_%04d.png
       uv run --with pillow python docs/build-demo-gif.py frames docs/demo.gif 120 64

The last two numbers trade size against smoothness: 120 milliseconds a frame,
and a 64 colour palette, which is enough for this interface. Do not lower the
duration much: identical frames are collapsed into one long frame, so a small
number makes a page that barely moves look like a still image. A frame is held
for at most 1200 milliseconds, which is what keeps a quiet moment from reading
as a freeze. Keep the result under about five megabytes, which is what a README
can carry without becoming unpleasant to open.

The demo target uses documentation address ranges, so the network column stays
empty in the recording even on a machine that has the address table. That is
correct: those ranges are announced by nobody.
