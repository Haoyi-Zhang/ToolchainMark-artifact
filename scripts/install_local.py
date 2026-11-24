#!/usr/bin/env python3
"""Create a local validation environment for this checkout without downloads."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parents[1]
MARKER_NAME = "toolchainmark-environment.json"
SCIENCE_DISTRIBUTIONS = ("numpy", "pandas", "scipy")


def environment_python(directory: Path) -> Path:
    windows = directory / "Scripts" / "python.exe"
    return windows if windows.is_file() else directory / "bin" / "python"


def query_environment(python: Path) -> dict:
    program = r'''
import importlib.metadata as metadata
import json, site, sys
names = ("numpy", "pandas", "scipy")
versions = {}
for name in names:
    try:
        versions[name] = metadata.version(name)
    except metadata.PackageNotFoundError:
        versions[name] = None
print(json.dumps({
    "prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "site_packages": site.getsitepackages(),
    "versions": versions,
}))
'''
    return json.loads(subprocess.check_output([str(python), "-B", "-c", program], text=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", default=".venv", type=Path)
    parser.add_argument("--replace", action="store_true")
    parser.add_argument(
        "--with-system-science",
        action="store_true",
        help="allow the base interpreter's NumPy/Pandas/SciPy stack for the CTF compatibility checks",
    )
    args = parser.parse_args()
    target = args.directory.expanduser().resolve()
    if target.exists():
        if not args.replace:
            parser.error(f"environment already exists: {target}")
        shutil.rmtree(target)

    venv.EnvBuilder(
        with_pip=False,
        clear=False,
        symlinks=False,
        system_site_packages=args.with_system_science,
    ).create(target)
    python = environment_python(target)
    details = query_environment(python)
    sites = [Path(item).resolve() for item in details["site_packages"]]
    local_sites = [path for path in sites if path == target or target in path.parents]
    if not local_sites:
        parser.error(f"cannot identify an environment site-packages directory: {sites}")
    site_dir = local_sites[0]
    site_dir.mkdir(parents=True, exist_ok=True)

    # Register only this checkout in core mode. Science mode additionally
    # exposes the invoking interpreter's already-installed scientific stack;
    # those roots and versions are recorded and checked on every validation.
    host_sites = [Path(item).resolve() for item in sys.path
                  if "site-packages" in item and Path(item).is_dir()] if args.with_system_science else []
    pth_lines = [*(str(path) for path in host_sites), str(ROOT / "src"), str(ROOT), str(ROOT / "tests")]
    (site_dir / "toolchainmark-local.pth").write_text(
        "\n".join(dict.fromkeys(pth_lines)) + "\n", encoding="utf-8"
    )

    details = query_environment(python)
    external_sites = [str(path) for path in host_sites]
    versions = details["versions"]
    missing = [name for name in SCIENCE_DISTRIBUTIONS if not versions.get(name)] if args.with_system_science else []
    if missing:
        shutil.rmtree(target)
        parser.error("science environment is missing: " + ", ".join(missing))

    marker = {
        "schema": "toolchainmark-local-environment-v1",
        "mode": "science" if args.with_system_science else "core",
        "repository": str(ROOT),
        "environment": str(target),
        "local_site_packages": str(site_dir),
        "allowed_external_site_packages": external_sites,
        "science_distributions": versions if args.with_system_science else {},
        "network_used": False,
    }
    (target / MARKER_NAME).write_text(json.dumps(marker, indent=2) + "\n", encoding="utf-8")

    if (target / "bin").is_dir():
        wrapper = target / "bin" / "toolchainmark"
        wrapper.write_text(
            "#!/bin/sh\nexport PYTHONDONTWRITEBYTECODE=1\nexec \"$(dirname \"$0\")/python\" -B -m toolchainmark.cli \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

    smoke_modules = "import toolchainmark, contract_runtime"
    if args.with_system_science:
        smoke_modules += ", numpy, pandas, scipy"
    smoke = subprocess.run(
        [str(python), "-B", "-c", smoke_modules + "; print('installation: PASS')"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1"),
    )
    report = dict(marker)
    report.update({
        "python": str(python),
        "smoke_returncode": smoke.returncode,
        "smoke_output": smoke.stdout.strip(),
        "smoke_error": smoke.stderr.strip(),
    })
    print(json.dumps(report, indent=2))
    return smoke.returncode


if __name__ == "__main__":
    raise SystemExit(main())
