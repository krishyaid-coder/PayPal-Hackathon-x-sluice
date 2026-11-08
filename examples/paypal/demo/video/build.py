#!/usr/bin/env python3
"""Render the origin-gate demo film to a 1920x1080 mp4."""

from __future__ import annotations

import asyncio
import subprocess
import wave
from pathlib import Path

import edge_tts

ROOT = Path(__file__).resolve().parent
FRAMES = ROOT / "frames"
AUDIO = ROOT / "audio"
OUT = ROOT.parent / "sluice-origin-gate.mp4"
FILM = ROOT / "film.html"
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
FF = ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error"]

# Jenny is brighter than macOS Samantha; slight rate/pitch lift for curiosity.
VOICE = "en-US-JennyNeural"
RATE = "+12%"
PITCH = "+8Hz"

HOLD = 0.22

SCENES = [
    (
        "1",
        "Wait. An AI agent just tried to invoice an attacker on PayPal. This is the call that never left the machine.",
    ),
    (
        "2",
        "Same consulting job. Two invoices. One of them is trying to steal the payee. Spot the poison line?",
    ),
    (
        "3",
        "So where do we stop it? Right here. In front of PayPal. If that email came from poisoned content, the money call dies here.",
    ),
    (
        "4",
        "Watch this. The agent reads the poison, then tries to bill that payee. Blocked! The email originated in read file. We stored a fingerprint, not the raw address.",
    ),
    (
        "5",
        "And this is live. Every money-moving call. Detector, masked payee, gated argument.",
    ),
    (
        "6",
        "Same session. Different business. That one goes through. So this is not a block list. It is origin.",
    ),
    (
        "7",
        "PayPal sandbox. Real MCP. Fingerprints, not values. Built on Sluice.",
    ),
]


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def wav_duration(path: Path) -> float:
    with wave.open(str(path), "r") as fh:
        return fh.getnframes() / float(fh.getframerate())


async def speak(text: str, mp3: Path) -> None:
    comm = edge_tts.Communicate(text, VOICE, rate=RATE, pitch=PITCH)
    await comm.save(str(mp3))


def screenshot(num: str, file_url: str, png: Path) -> None:
    run(
        [
            str(CHROME),
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--allow-file-access-from-files",
            "--force-device-scale-factor=1",
            "--window-size=1920,1080",
            "--virtual-time-budget=4000",
            f"--screenshot={png}",
            f"{file_url}?s={num}",
        ]
    )


def main() -> None:
    AUDIO.mkdir(parents=True, exist_ok=True)
    FRAMES.mkdir(parents=True, exist_ok=True)
    file_url = FILM.resolve().as_uri()

    pngs: list[Path] = []
    wavs: list[Path] = []
    durs: list[float] = []

    for num, line in SCENES:
        png = FRAMES / f"scene-{num}.png"
        mp3 = AUDIO / f"scene-{num}.mp3"
        wav = AUDIO / f"scene-{num}.wav"
        screenshot(num, file_url, png)
        asyncio.run(speak(line, mp3))
        run(
            FF
            + [
                "-i",
                str(mp3),
                "-ar",
                "48000",
                "-ac",
                "1",
                "-c:a",
                "pcm_s16le",
                str(wav),
            ]
        )
        dur = wav_duration(wav) + HOLD
        pngs.append(png)
        wavs.append(wav)
        durs.append(dur)
        print(f"scene {num}: {dur:.2f}s")

    cmd: list[str] = FF.copy()
    filters: list[str] = []
    concat_pads: list[str] = []
    for i, (png, wav, dur) in enumerate(zip(pngs, wavs, durs)):
        cmd += ["-loop", "1", "-framerate", "30", "-t", f"{dur:.3f}", "-i", str(png)]
        cmd += ["-i", str(wav)]
        fade = 0.10
        fade_out = max(dur - fade, 0)
        v, a = i * 2, i * 2 + 1
        filters.append(
            f"[{v}:v]scale=1920:1080,fps=30,format=yuv420p,"
            f"fade=t=in:st=0:d={fade:.2f},fade=t=out:st={fade_out:.2f}:d={fade:.2f},"
            f"setpts=PTS-STARTPTS[v{i}]"
        )
        filters.append(
            f"[{a}:a]aformat=sample_fmts=fltp:sample_rates=48000:channel_layouts=mono,"
            f"apad=pad_dur={HOLD:.2f},atrim=0:{dur:.3f},asetpts=PTS-STARTPTS[a{i}]"
        )
        concat_pads.append(f"[v{i}][a{i}]")

    n = len(SCENES)
    filters.append("".join(concat_pads) + f"concat=n={n}:v=1:a=1[v][a]")
    cmd += [
        "-filter_complex",
        ";".join(filters),
        "-map",
        "[v]",
        "-map",
        "[a]",
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-r",
        "30",
        "-c:a",
        "aac",
        "-profile:a",
        "aac_low",
        "-b:a",
        "160k",
        "-ac",
        "1",
        "-ar",
        "48000",
        "-movflags",
        "+faststart",
        str(OUT),
    ]
    run(cmd)
    probe = subprocess.check_output(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=nw=1:nk=1",
            str(OUT),
        ],
        text=True,
    ).strip()
    print(f"wrote {OUT} ({float(probe):.1f}s)")


if __name__ == "__main__":
    main()
