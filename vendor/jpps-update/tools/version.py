#!/usr/bin/env python3
"""Date versions for releases (Jeff 2026-11-22: YY.MM.DD.hhmm, Chicago time).

    tools/version.py now                 26.1122.2130    the Cargo.toml form for this minute
    tools/version.py display 26.1122.2130 26.11.22.2130  what tags, files, installers and the app show
    tools/version.py android 26.11.22.2130 3330090       Android versionCode (minutes since 2020)
    tools/version.py ios 26.11.22.2130   26.11.22        iOS/macOS CFBundleShortVersionString
"""
import sys
from datetime import datetime
from zoneinfo import ZoneInfo


def display(cargo):
    if "-" in cargo:  # a Beta keeps its suffix
        base, _, rest = cargo.partition("-")
        return f"{display(base)}-{rest}"
    p = cargo.split(".")
    try:
        yy, mmdd, hhmm = (int(x) for x in p)
    except ValueError:
        return cargo
    if len(p) == 3 and 20 <= yy <= 99 and 1 <= mmdd // 100 <= 12 and 1 <= mmdd % 100 <= 31 and hhmm // 100 <= 23 and hhmm % 100 <= 59:
        return f"{yy:02}.{mmdd // 100:02}.{mmdd % 100:02}.{hhmm:04}"
    return cargo


def android(disp):
    yy, mm, dd, hhmm = (int(x) for x in disp.split("."))
    return ((yy - 20) * 372 + (mm - 1) * 31 + (dd - 1)) * 1440 + (hhmm // 100) * 60 + hhmm % 100


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "now":
        t = datetime.now(ZoneInfo("America/Chicago"))
        print(f"{t.year % 100}.{t.month * 100 + t.day}.{t.hour * 100 + t.minute}")
    elif cmd == "display":
        print(display(sys.argv[2]))
    elif cmd == "android":
        print(android(sys.argv[2]))
    elif cmd == "ios":
        print(".".join(str(int(x)) for x in sys.argv[2].split(".")[:3]))
    else:
        sys.exit(__doc__)
