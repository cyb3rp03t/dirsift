"""Builds docs/demo.gif from the frames of a recording.

Usage, from the repository root:

    ffmpeg -i docs/demo-recording/<recording>.webm -r 5 -s 700x438 frames/f_%04d.png
    uv run --with pillow python docs/build-demo-gif.py frames docs/demo.gif 11 64

The three numbers are the frame folder, the milliseconds each frame is held
(11 here means the recording plays back about twice as fast as it happened) and
the palette size. Frames identical to the one before are dropped and the one
before is held for longer instead, which is what keeps a recording of a mostly
static page small enough for a README.
"""

import sys
from pathlib import Path

from PIL import Image, ImageChops

FRAMES = Path(sys.argv[1])
OUT = Path(sys.argv[2])
STEP = int(sys.argv[3]) if len(sys.argv) > 3 else 100
COLORS = int(sys.argv[4]) if len(sys.argv) > 4 else 64

frames = sorted(FRAMES.glob("*.png"))
if not frames:
    raise SystemExit("no frames in " + str(FRAMES))

kept: list[Image.Image] = []
durations: list[int] = []
previous = None

for path in frames:
    image = Image.open(path).convert("RGB")
    if previous is not None and not ImageChops.difference(image, previous).getbbox():
        durations[-1] += STEP
        continue
    kept.append(image.convert("P", palette=Image.ADAPTIVE, colors=COLORS))
    durations.append(STEP)
    previous = image

kept[0].save(
    OUT,
    save_all=True,
    append_images=kept[1:],
    duration=durations,
    loop=0,
    optimize=True,
    disposal=1,
)

print(
    "frames in:", len(frames),
    "| frames kept:", len(kept),
    "| seconds:", round(sum(durations) / 1000, 1),
    "|", OUT.name, round(OUT.stat().st_size / 1024 / 1024, 2), "MB",
)
