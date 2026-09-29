#!/usr/bin/env python3
"""Record docs/assets/demo.gif: screenshots of the status page (and the Grafana cost dashboard) taken while
scripts/demo.sh runs, with a caption bar that follows the demo's own narration, assembled with Pillow.

  .venv/Scripts/python scripts/record_demo_gif.py                  run demo.sh and record it (about 4 minutes)
  .venv/Scripts/python scripts/record_demo_gif.py --frames-only    only capture stills of the two pages, no demo

Needs the running stack (bash scripts/up.sh), Pillow (`pip install pillow`) and a Chromium-based browser (Chrome or
Edge, headless mode; set BROWSER=/path/to/chrome to choose one). Each frame is a fresh headless load of the page at
1280 px, so nothing is injected into the page and no browser extension is involved. The demo runs with
DEMO_CLEAR_QUEUE=1 so the discovery queue starts empty (stale proposals from earlier runs are rejected, audited).
Outputs: docs/assets/demo.gif, docs/assets/status-*.png (one still per scene), docs/assets/grafana-cost.png.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
STATUS_URL = os.environ.get("STATUS_URL", "http://127.0.0.1:8400/")
GRAFANA_URL = os.environ.get("GRAFANA_URL",
                             "http://127.0.0.1:3400/d/govpilot-cost?orgId=1&from=now-15m&to=now&refresh=&kiosk")
BROWSERS = [os.environ.get("BROWSER", ""), r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", shutil.which("google-chrome") or "",
            shutil.which("chromium") or "", shutil.which("chromium-browser") or "", shutil.which("microsoft-edge") or ""]
W, H = 1280, 1000           # capture size of the status page
GIF_W = 960                 # width of the GIF
SCENE_RE = re.compile(r"\[\s*(\d+)s\]\s+(\d)/6\s+(.*)")
# scene number -> still file (the last frame of the scene: the state the scene builds up to)
STILLS = {"2": "status-rogue-spend.png", "3": "status-stopped.png", "4": "status-cannot-restart.png",
          "5": "status-discovery.png", "6": "status-audit.png"}


def bash() -> str:
    """Git Bash on Windows (a bare `bash` on PATH may be WSL's, which cannot see the repo's .venv)."""
    for b in (os.environ.get("BASH_EXE", ""), r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if b and Path(b).exists():
            return b
    return "bash"


def browser() -> str:
    for b in BROWSERS:
        if b and Path(b).exists():
            return b
    raise SystemExit("no Chrome/Edge found; set BROWSER=/path/to/chrome")


def shot(url: str, out: Path, *, w: int = W, h: int = H, budget_ms: int = 4000, scheme: str = "dark") -> bool:
    """One headless screenshot (own profile directory, so shots can run side by side)."""
    prof = tempfile.mkdtemp(prefix="demo-shot-")
    try:
        cmd = [browser(), "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
               f"--window-size={w},{h}", f"--virtual-time-budget={budget_ms}", f"--user-data-dir={prof}",
               f"--force-prefers-color-scheme={scheme}", "--no-first-run", "--no-default-browser-check",
               f"--screenshot={out}", url]
        subprocess.run(cmd, capture_output=True, timeout=60)
        return out.exists() and out.stat().st_size > 2000
    except (subprocess.TimeoutExpired, OSError):
        return False
    finally:
        shutil.rmtree(prof, ignore_errors=True)


def font(size: int):
    for f in (r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        if Path(f).exists():
            return ImageFont.truetype(f, size)
    return ImageFont.load_default()


def caption(img: Image.Image, text: str, sub: str = "") -> Image.Image:
    """Bottom caption bar, so the GIF explains itself without the terminal."""
    img = img.convert("RGB")
    bar_h = 84
    out = Image.new("RGB", (img.width, img.height + bar_h), (11, 18, 32))
    out.paste(img, (0, 0))
    d = ImageDraw.Draw(out)
    d.text((22, img.height + 10), text, font=font(28), fill=(255, 255, 255))
    if sub:
        d.text((22, img.height + 50), sub, font=font(20), fill=(148, 163, 184))
    return out


def palette_from(frames: list[Image.Image], colors: int = 160) -> Image.Image:
    """One shared palette built from a sample of ALL frames (red stop buttons, green bars and the caption bar included)."""
    sample = frames[:: max(1, len(frames) // 10)][:10]
    w, h = sample[0].size
    mosaic = Image.new("RGB", (w, h * len(sample)))
    for i, f in enumerate(sample):
        mosaic.paste(f, (0, i * h))
    return mosaic.quantize(colors=colors, method=Image.Quantize.MEDIANCUT)


def assemble(frames: list[tuple[Image.Image, int]], out: Path) -> None:
    scale = GIF_W / frames[0][0].width
    rgb = [f.resize((GIF_W, round(f.height * scale)), Image.LANCZOS) for f, _ in frames]
    pal = palette_from(rgb)
    q = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in rgb]
    q[0].save(out, save_all=True, append_images=q[1:], duration=[d for _, d in frames], loop=0, optimize=True, disposal=1)


def run(a) -> int:
    ASSETS.mkdir(parents=True, exist_ok=True)
    frames: list[tuple[Image.Image, int]] = []       # (image, duration ms)
    tmp = Path(tempfile.mkdtemp(prefix="demo-frames-"))
    state = {"scene": "Three governed agents, live", "n": "", "sub": "", "done": False}
    last_of_scene: dict[str, Image.Image] = {}

    def follow(proc: subprocess.Popen) -> None:
        for raw in proc.stdout:                       # type: ignore[union-attr]
            line = raw.rstrip()
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            m = SCENE_RE.match(clean)
            if m:
                state["scene"], state["n"], state["sub"] = m.group(3), m.group(2), ""
            elif clean.startswith(("t+", "stop ", "proposal ", "audit hash chain", "container running", "contained")):
                state["sub"] = clean[:130]
            print(line, flush=True)
        state["done"] = True

    proc = None
    if not a.frames_only:
        env = {**os.environ, "PYTHONUNBUFFERED": "1", "DEMO_CLEAR_QUEUE": "1"}
        proc = subprocess.Popen([bash(), "scripts/demo.sh"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", env=env)
        threading.Thread(target=follow, args=(proc,), daemon=True).start()

    n = 0
    prev_scene = None
    t_start = time.time()
    while True:
        out = tmp / f"f{n:03d}.png"
        if shot(STATUS_URL, out):
            img = Image.open(out).convert("RGB")
            scene, num = state["scene"], state["n"]
            title = f"{num}/6  {scene}" if num else scene
            hold = a.frame_ms * (3 if prev_scene is not None and prev_scene != scene else 1)   # linger when a scene starts
            frames.append((caption(img, title, state["sub"]), hold))
            prev_scene = scene
            if num in STILLS:
                last_of_scene[num] = img.copy()
            n += 1
        if a.frames_only or state["done"] or time.time() - t_start > a.max_seconds:
            break
    if proc is not None:
        try:
            proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Grafana: the cost dashboard afterwards (the rogue spike is inside the last 15 minutes)
    g = tmp / "grafana.png"
    if shot(GRAFANA_URL, g, w=1400, h=1100, budget_ms=15000):
        gi = Image.open(g).convert("RGB")
        gi.save(ASSETS / "grafana-cost.png", optimize=True)
        gi_small = gi.resize((W, round(gi.height * W / gi.width)), Image.LANCZOS)
        cap = caption(gi_small, "Cost by agent, team and run",
                      "Grafana over OpenLIT and ClickHouse: the rogue spike is attributed to coding-agent")
        frames += [(cap, a.frame_ms * 6)]
    for num, name in STILLS.items():
        if num in last_of_scene:
            last_of_scene[num].save(ASSETS / name, optimize=True)

    if not frames:
        print("no frames captured")
        return 1
    # equal frame sizes for the GIF (the Grafana frame is taller than the status frames)
    hmax = max(f.height for f, _ in frames)
    padded = []
    for f, d in frames:
        canvas = Image.new("RGB", (f.width, hmax), (11, 18, 32))
        canvas.paste(f, (0, 0))
        padded.append((canvas, d))
    assemble(padded, ASSETS / "demo.gif")
    size = (ASSETS / "demo.gif").stat().st_size
    print(f"wrote {ASSETS / 'demo.gif'}: {len(padded)} frames, {size / 1e6:.1f} MB; stills: {sorted(last_of_scene)}")
    shutil.rmtree(tmp, ignore_errors=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--frames-only", action="store_true")
    ap.add_argument("--frame-ms", type=int, default=350, help="display time of one frame in the GIF")
    ap.add_argument("--max-seconds", type=int, default=420)
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
