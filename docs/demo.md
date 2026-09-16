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
       uv run --with pillow python docs/build-demo-gif.py frames docs/demo.gif 11 64

The last two numbers trade size against smoothness: 11 milliseconds a frame
plays back about twice as fast as the session ran, and a 64 colour palette is
enough for this interface. Keep the result under about five megabytes, which is
what a README can carry without becoming unpleasant to open.
