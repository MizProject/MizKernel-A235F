#!/usr/bin/env python3
"""Central build and environment verification tool for MizKernel-A235F."""

from __future__ import annotations

import argparse
import configparser
import dataclasses
import getpass
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# Host CLI binaries needed to configure and compile Linux 4.19 kernels.
# Maps binary name -> (required, Ubuntu/Debian apt package hint).
HOST_TOOL_SPECS: Dict[str, Tuple[bool, str]] = {
    "make": (True, "make"),
    "gcc": (True, "build-essential"),
    "g++": (True, "build-essential"),
    "ld": (True, "binutils"),
    "ar": (True, "binutils"),
    "flex": (True, "flex"),
    "bison": (True, "bison"),
    "bc": (True, "bc"),
    "perl": (True, "perl"),
    "awk": (True, "gawk"),
    "tar": (True, "tar"),
    "gzip": (True, "gzip"),
    "xz": (True, "xz-utils"),
    "cpio": (True, "cpio"),
    "rsync": (True, "rsync"),
    "git": (True, "git"),
    "pkg-config": (True, "pkg-config"),
    "openssl": (True, "openssl"),
    "python3": (True, "python3"),
    "zip": (False, "zip"),
    "unzip": (False, "unzip"),
    "lz4": (False, "lz4"),
    "zstd": (False, "zstd"),
    "ccache": (False, "ccache"),
}

# C library/header probes compiled against HOSTCC to verify -dev packages.
HEADER_PROBES: List[Tuple[str, str, List[str], str, bool]] = [
    (
        "openssl-dev",
        "#include <openssl/opensslv.h>\n#include <openssl/evp.h>\nint main(void){return 0;}\n",
        ["-lcrypto"],
        "libssl-dev",
        True,
    ),
    (
        "libelf-dev",
        "#include <libelf.h>\n#include <gelf.h>\nint main(void){return 0;}\n",
        ["-lelf"],
        "libelf-dev",
        True,
    ),
    (
        "zlib-dev",
        "#include <zlib.h>\nint main(void){return 0;}\n",
        ["-lz"],
        "zlib1g-dev",
        True,
    ),
    (
        "ncurses-dev",
        "#if __has_include(<ncursesw/ncurses.h>)\n#include <ncursesw/ncurses.h>\n"
        "#elif __has_include(<ncurses/ncurses.h>)\n#include <ncurses/ncurses.h>\n"
        "#else\n#include <ncurses.h>\n#endif\nint main(void){return 0;}\n",
        [],
        "libncurses-dev",
        False,
    ),
]

ARCH_CONFIG_ALIASES: Dict[str, Tuple[str, ...]] = {
    "arm64": ("aarch64", "arm64"),
    "arm": ("arm",),
    "x86_64": ("x86_64",),
    "x86": ("x86", "x86_64"),
}

ARCH_DEFAULT_TRIPLES: Dict[str, Tuple[str, ...]] = {
    "arm64": ("aarch64-linux-android-", "aarch64-linux-gnu-", "aarch64-none-linux-gnu-"),
    "arm": ("arm-linux-androideabi-", "arm-linux-gnueabi-", "arm-linux-gnueabihf-"),
    "x86_64": ("x86_64-linux-gnu-",),
}

CRITICAL_EXEC_SCRIPTS: Tuple[str, ...] = (
    "scripts/clang-version.sh",
    "scripts/gcc-version.sh",
    "scripts/ld-version.sh",
    "scripts/config",
    "arch/arm64/kernel/vdso/gen_vdso_offsets.sh",
)


@dataclasses.dataclass
class CheckResult:
    """Represents a single environment or toolchain diagnostic check."""

    name: str
    ok: bool
    required: bool
    detail: str
    hint_pkg: Optional[str] = None


@dataclasses.dataclass
class ResolvedToolchains:
    """Resolved compiler, cross-binutils, linker, and DTC paths."""

    clang: Optional[Path]
    clang_bin_dir: Optional[Path]
    clang_version: Optional[str]
    cross_compile: Optional[str]
    cross_bin_dir: Optional[Path]
    cross_ld_version: Optional[str]
    clang_triple: str
    lld: Optional[Path]
    llvm_tools: Dict[str, Path]
    dtc: Optional[Path]
    dtc_version: Optional[str]


def parse_os_release(path: Path = Path("/etc/os-release")) -> Dict[str, str]:
    """Parse key=value pairs from /etc/os-release if available."""
    info: Dict[str, str] = {}
    if not path.is_file():
        return info
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        info[key] = value.strip().strip('"').strip("'")
    return info


def detect_runtime_context() -> Dict[str, object]:
    """Inspect OS, container, CI, CPU, memory, and disk telemetry."""
    os_release = parse_os_release()
    mem_gib: Optional[float] = None
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    mem_gib = round(int(parts[1]) / (1024 * 1024), 2)
                break

    container_name = os.environ.get("CONTAINER_ID")
    in_container = bool(container_name) or Path("/run/.containerenv").exists() or Path("/.dockerenv").exists()
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "os_pretty": os_release.get("PRETTY_NAME", platform.platform()),
        "os_id": os_release.get("ID", "unknown"),
        "os_version": os_release.get("VERSION_ID", "unknown"),
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count() or 1,
        "mem_gib": mem_gib,
        "in_container": in_container,
        "container_id": container_name,
        "github_actions": os.environ.get("GITHUB_ACTIONS", "").lower() == "true",
    }


def maybe_reexec_in_distrobox(argv: Sequence[str], distrobox_name: Optional[str]) -> None:
    """Re-execute this script inside the requested distrobox container if not already in it."""
    if not distrobox_name:
        return
    if os.environ.get("MIZ_INSIDE_DISTROBOX") == distrobox_name or os.environ.get("CONTAINER_ID") == distrobox_name:
        return

    distrobox_bin = shutil.which("distrobox")
    if not distrobox_bin:
        raise RuntimeError(
            f"--distrobox '{distrobox_name}' was requested, but 'distrobox' was not found in PATH."
        )

    filtered: List[str] = []
    skip_next = False
    for token in argv:
        if skip_next:
            skip_next = False
            continue
        if token == "--distrobox":
            skip_next = True
            continue
        if token.startswith("--distrobox="):
            continue
        filtered.append(token)

    env_cmd = [
        distrobox_bin,
        "enter",
        distrobox_name,
        "--",
        "env",
        f"MIZ_INSIDE_DISTROBOX={distrobox_name}",
        "python3",
        str(Path(__file__).resolve()),
        *filtered,
    ]
    print(f"[miz_build] Entering distrobox '{distrobox_name}'...")
    result = subprocess.run(env_cmd)
    sys.exit(result.returncode)


def parse_gitmodules(src_dir: Path) -> List[Tuple[str, Path, str]]:
    """Return (name, relative_path, url) entries parsed from .gitmodules."""
    gitmodules = src_dir / ".gitmodules"
    if not gitmodules.is_file():
        return []
    parser = configparser.ConfigParser()
    parser.read(gitmodules, encoding="utf-8")
    entries: List[Tuple[str, Path, str]] = []
    for section in parser.sections():
        path_val = parser.get(section, "path", fallback="").strip()
        url_val = parser.get(section, "url", fallback="").strip()
        if not path_val or not url_val:
            continue
        name = section
        match = re.match(r'^submodule\s+"(.+)"$', section)
        if match:
            name = match.group(1)
        entries.append((name, Path(path_val), url_val))
    return entries


def probe_git_remote(url: str, timeout_s: int = 12) -> Tuple[bool, str]:
    """Non-interactively verify whether a remote git repository is reachable."""
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        proc = subprocess.run(
            ["git", "ls-remote", "--heads", url],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return False, "timed out probing remote"
    except OSError as exc:
        return False, str(exc)

    if proc.returncode == 0:
        return True, "reachable"
    err = (proc.stderr or proc.stdout).strip().splitlines()
    return False, err[-1] if err else f"exit code {proc.returncode}"


def dir_has_executables(path: Path) -> bool:
    """Check whether a toolchain directory already contains executable binaries."""
    bin_dir = path / "bin"
    if not bin_dir.is_dir():
        return False
    return any(p.is_file() and os.access(p, os.X_OK) for p in bin_dir.iterdir())


def fetch_toolchains(
    src_dir: Path,
    toolchain_dir: Path,
    arch: str,
    requested_names: Sequence[str],
    url_overrides: Sequence[str],
    force: bool = False,
    fetch_all: bool = False,
) -> int:
    """Clone missing toolchain repositories declared in .gitmodules or CLI overrides."""
    entries = parse_gitmodules(src_dir)
    override_map: Dict[str, str] = {}
    for item in url_overrides:
        if "=" not in item:
            raise ValueError(f"Invalid --toolchain-url '{item}'. Expected <path_or_name>=<git_url>.")
        key, val = item.split("=", 1)
        override_map[key.strip()] = val.strip()

    # Select toolchain entries from .gitmodules (plus any purely CLI-specified overrides).
    selected: List[Tuple[Path, str]] = []
    seen_paths = set()
    for name, rel_path, url in entries:
        if rel_path.parts and rel_path.parts[0] == "toolchain":
            effective_path = toolchain_dir / Path(*rel_path.parts[1:])
        elif not requested_names:
            continue
        else:
            effective_path = src_dir / rel_path

        short_name = rel_path.name
        if requested_names and short_name not in requested_names and str(rel_path) not in requested_names and name not in requested_names:
            continue
        url = override_map.get(str(rel_path), override_map.get(short_name, url))
        selected.append((effective_path, url))
        seen_paths.add(str(effective_path))

    for key, url in override_map.items():
        candidate = Path(key) if Path(key).is_absolute() else (toolchain_dir / key if "/" not in key else src_dir / key)
        if str(candidate) not in seen_paths:
            selected.append((candidate, url))

    if not selected:
        print("[miz_build] No toolchain entries matched from .gitmodules or overrides.")
        return 1

    toolchain_dir.mkdir(parents=True, exist_ok=True)
    fetched_any = False
    failures: List[str] = []

    for dest, url in selected:
        if not requested_names and not fetch_all and not force:
            current = resolve_toolchains(src_dir=src_dir, toolchain_dir=toolchain_dir, arch=arch)
            if current.clang and current.cross_compile:
                break

        if dest.exists() and dir_has_executables(dest) and not force:
            print(f"[miz_build] Toolchain already present: {dest}")
            continue
        if dest.exists() and force:
            shutil.rmtree(dest)

        ok, detail = probe_git_remote(url)
        if not ok:
            msg = f"Skipping unreachable toolchain '{dest.name}' ({url}): {detail}"
            if requested_names:
                failures.append(msg)
                print(f"[miz_build] ERROR: {msg}", file=sys.stderr)
            else:
                print(f"[miz_build] WARN: {msg}")
            continue

        print(f"[miz_build] Cloning {url} -> {dest}")
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        proc = subprocess.run(
            ["git", "clone", "--depth=1", url, str(dest)],
            env=env,
        )
        if proc.returncode != 0:
            msg = f"Failed to clone {url} into {dest} (exit {proc.returncode})"
            failures.append(msg)
            print(f"[miz_build] ERROR: {msg}", file=sys.stderr)
        else:
            fetched_any = True

    # Ensure at least a Clang compiler and cross-linker are now resolvable.
    resolved = resolve_toolchains(src_dir=src_dir, toolchain_dir=toolchain_dir, arch=arch)
    if failures and requested_names:
        return 1
    if not resolved.clang or not resolved.cross_compile:
        print(
            "[miz_build] ERROR: Toolchain bootstrap completed without both a usable Clang and cross-binutils.",
            file=sys.stderr,
        )
        return 1
    if fetched_any:
        print("[miz_build] Toolchains ready.")
    return 0


def discover_defconfigs(src_dir: Path, arch: str) -> List[str]:
    """List available defconfig paths relative to arch/<arch>/configs."""
    configs_dir = src_dir / "arch" / arch / "configs"
    if not configs_dir.is_dir():
        return []
    found = sorted(
        p.relative_to(configs_dir).as_posix()
        for p in configs_dir.rglob("*_defconfig")
        if p.is_file()
    )
    return found


def resolve_defconfig(src_dir: Path, arch: str, explicit: Optional[str]) -> str:
    """Resolve and validate the target defconfig without hardcoding a single filename."""
    configs_dir = src_dir / "arch" / arch / "configs"
    available = discover_defconfigs(src_dir, arch)
    if explicit:
        candidate = configs_dir / explicit
        if candidate.is_file():
            return explicit
        matches = [c for c in available if Path(c).name == explicit or c == explicit]
        if len(matches) == 1:
            return matches[0]
        raise FileNotFoundError(
            f"Defconfig '{explicit}' not found under {configs_dir}. Available: {', '.join(available) or 'none'}"
        )

    if not available:
        raise FileNotFoundError(f"No *_defconfig files found under {configs_dir}.")
    if len(available) == 1:
        return available[0]

    # Prefer project-customized defconfigs over stock vendor/arch defaults if multiple exist.
    custom = [c for c in available if "miz" in Path(c).name.lower()]
    if len(custom) == 1:
        return custom[0]
    vendor = [c for c in available if c.startswith("vendor/")]
    if len(vendor) == 1:
        return vendor[0]
    return custom[0] if custom else available[0]


def infer_clang_triple(src_dir: Path, arch: str, explicit: Optional[str], cross_compile: Optional[str]) -> str:
    """Infer CLANG_TRIPLE from explicit args, build.config.<arch>, cross prefix, or arch."""
    if explicit:
        return explicit

    for alias in ARCH_CONFIG_ALIASES.get(arch, (arch,)):
        cfg = src_dir / f"build.config.{alias}"
        if cfg.is_file():
            for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("CROSS_COMPILE="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val

    if cross_compile:
        base = Path(cross_compile).name
        if base.endswith("-"):
            return base

    defaults = ARCH_DEFAULT_TRIPLES.get(arch)
    return defaults[1] if defaults and len(defaults) > 1 else (defaults[0] if defaults else f"{arch}-linux-gnu-")


def _ordered_toolchain_subdirs(src_dir: Path, toolchain_dir: Path, preferred: Optional[str] = None) -> List[Path]:
    """Order subdirectories inside toolchain_dir using preference, .gitmodules order, then name."""
    if not toolchain_dir.is_dir():
        return []
    existing = {p.name: p for p in toolchain_dir.iterdir() if p.is_dir()}
    ordered: List[Path] = []
    if preferred and preferred in existing:
        ordered.append(existing.pop(preferred))
    for _, rel_path, _ in parse_gitmodules(src_dir):
        if rel_path.name in existing:
            ordered.append(existing.pop(rel_path.name))
    for name in sorted(existing):
        ordered.append(existing[name])
    return ordered


def _run_version_line(cmd: Sequence[str]) -> Optional[str]:
    """Run a quick --version command and return its first non-empty output line."""
    try:
        proc = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            return line
    return None


def _resolve_executable_cand(src_dir: Path, spec: str) -> Optional[Path]:
    """Resolve a path or command name to an executable file if it exists."""
    cand = Path(spec)
    if not cand.is_absolute():
        rel = (src_dir / cand).resolve()
        if rel.is_file() and os.access(rel, os.X_OK):
            return rel
        found = shutil.which(spec)
        if found:
            return Path(found)
        return None
    if cand.is_file() and os.access(cand, os.X_OK):
        return cand
    return None


def _resolve_cross_prefix(src_dir: Path, prefix: str) -> Optional[Tuple[str, Path]]:
    """Validate a CROSS_COMPILE prefix and return (resolved_prefix, bin_dir) if tools exist."""
    for suffix in ("ld", "as", "elfedit"):
        cand = Path(f"{prefix}{suffix}")
        if not cand.is_absolute() and "/" in prefix:
            cand = (src_dir / cand).resolve()
            resolved_prefix = str(cand)[:-len(suffix)]
        else:
            resolved_prefix = prefix
        if cand.is_file() and os.access(cand, os.X_OK):
            return resolved_prefix, cand.parent
        found = shutil.which(f"{prefix}{suffix}")
        if found:
            return prefix, Path(found).parent
    return None


def resolve_toolchains(
    src_dir: Path,
    toolchain_dir: Path,
    arch: str,
    explicit_clang: Optional[str] = None,
    explicit_cross: Optional[str] = None,
    explicit_triple: Optional[str] = None,
    explicit_dtc: Optional[str] = None,
    preferred_toolchain: Optional[str] = None,
) -> ResolvedToolchains:
    """Dynamically locate Clang, cross-binutils, LLVM binutils, and DTC."""
    clang_path: Optional[Path] = None
    if explicit_clang:
        clang_path = _resolve_executable_cand(src_dir, explicit_clang)
        if clang_path is None:
            raise FileNotFoundError(f"Specified --clang executable not found or not executable: {explicit_clang}")
    else:
        for env_key in ("KERNEL_LLVM_BIN", "CLANG_BIN"):
            env_val = os.environ.get(env_key, "").strip()
            if not env_val:
                continue
            cand = _resolve_executable_cand(src_dir, env_val)
            if cand is not None:
                clang_path = cand
                break
            print(
                f"[miz_build] WARN: Ignoring non-existent env {env_key}={env_val}; falling back to auto-discovery.",
                file=sys.stderr,
            )

        if clang_path is None:
            for sub in _ordered_toolchain_subdirs(src_dir, toolchain_dir, preferred_toolchain):
                cand = sub / "bin" / "clang"
                if cand.is_file() and os.access(cand, os.X_OK):
                    clang_path = cand
                    break
        if clang_path is None:
            sys_clang = shutil.which("clang")
            if sys_clang:
                clang_path = Path(sys_clang)

    clang_bin_dir = clang_path.parent if clang_path else None
    clang_version = _run_version_line([str(clang_path), "--version"]) if clang_path else None

    llvm_tools: Dict[str, Path] = {}
    lld_path: Optional[Path] = None
    if clang_bin_dir:
        for tool in ("ld.lld", "llvm-ar", "llvm-nm", "llvm-objcopy", "llvm-objdump", "llvm-readelf", "llvm-strip"):
            cand = clang_bin_dir / tool
            if cand.is_file() and os.access(cand, os.X_OK):
                llvm_tools[tool] = cand
                if tool == "ld.lld":
                    lld_path = cand
    if lld_path is None:
        sys_lld = shutil.which("ld.lld")
        if sys_lld:
            lld_path = Path(sys_lld)

    cross_compile: Optional[str] = None
    cross_bin_dir: Optional[Path] = None
    if explicit_cross:
        resolved_cross = _resolve_cross_prefix(src_dir, explicit_cross)
        if resolved_cross is None:
            raise FileNotFoundError(f"Specified --cross-compile prefix tools not found: {explicit_cross}")
        cross_compile, cross_bin_dir = resolved_cross
    else:
        for env_key in ("BUILD_CROSS_COMPILE", "CROSS_COMPILE"):
            env_val = os.environ.get(env_key, "").strip()
            if not env_val:
                continue
            resolved_cross = _resolve_cross_prefix(src_dir, env_val)
            if resolved_cross is not None:
                cross_compile, cross_bin_dir = resolved_cross
                break
            print(
                f"[miz_build] WARN: Ignoring non-existent env {env_key}={env_val}; falling back to auto-discovery.",
                file=sys.stderr,
            )

        if cross_compile is None:
            prefixes = ARCH_DEFAULT_TRIPLES.get(arch, (f"{arch}-linux-gnu-",))
            for sub in _ordered_toolchain_subdirs(src_dir, toolchain_dir, preferred_toolchain):
                bin_dir = sub / "bin"
                if not bin_dir.is_dir():
                    continue
                for prefix in prefixes:
                    if (bin_dir / f"{prefix}ld").is_file() or (bin_dir / f"{prefix}as").is_file():
                        cross_compile = str(bin_dir / prefix)
                        cross_bin_dir = bin_dir
                        break
                if cross_compile:
                    break
                # Fallback: discover any *-ld inside bin/ for the target arch.
                arch_token = "aarch64" if arch == "arm64" else arch
                for item in sorted(bin_dir.glob(f"{arch_token}*-ld")):
                    if item.is_file() and os.access(item, os.X_OK):
                        cross_compile = str(item)[:-2]
                        cross_bin_dir = bin_dir
                        break
                if cross_compile:
                    break
        if cross_compile is None:
            prefixes = ARCH_DEFAULT_TRIPLES.get(arch, (f"{arch}-linux-gnu-",))
            for prefix in prefixes:
                sys_ld = shutil.which(f"{prefix}ld")
                if sys_ld:
                    cross_compile = prefix
                    cross_bin_dir = Path(sys_ld).parent
                    break

    cross_ld_version = None
    if cross_compile:
        ld_exe = Path(f"{cross_compile}ld")
        if ld_exe.is_file() or shutil.which(f"{cross_compile}ld"):
            cross_ld_version = _run_version_line([f"{cross_compile}ld", "--version"])

    clang_triple = infer_clang_triple(src_dir, arch, explicit_triple, cross_compile)

    dtc_path: Optional[Path] = None
    if explicit_dtc:
        dtc_path = _resolve_executable_cand(src_dir, explicit_dtc)
        if dtc_path is None:
            raise FileNotFoundError(f"Specified --dtc binary not found or not executable: {explicit_dtc}")
    else:
        env_dtc = os.environ.get("DTC_EXT", "").strip()
        if env_dtc:
            dtc_path = _resolve_executable_cand(src_dir, env_dtc)
            if dtc_path is None:
                print(
                    f"[miz_build] WARN: Ignoring non-existent env DTC_EXT={env_dtc}; falling back to auto-discovery.",
                    file=sys.stderr,
                )
        if dtc_path is None:
            repo_dtc = src_dir / "tools" / "dtc"
            if repo_dtc.is_file() and os.access(repo_dtc, os.X_OK):
                dtc_path = repo_dtc
            else:
                sys_dtc = shutil.which("dtc")
                if sys_dtc:
                    dtc_path = Path(sys_dtc)

    dtc_version = _run_version_line([str(dtc_path), "--version"]) if dtc_path and os.access(dtc_path, os.X_OK) else None

    return ResolvedToolchains(
        clang=clang_path,
        clang_bin_dir=clang_bin_dir,
        clang_version=clang_version,
        cross_compile=cross_compile,
        cross_bin_dir=cross_bin_dir,
        cross_ld_version=cross_ld_version,
        clang_triple=clang_triple,
        lld=lld_path,
        llvm_tools=llvm_tools,
        dtc=dtc_path,
        dtc_version=dtc_version,
    )


def _probe_c_header(gcc_bin: str, code: str, ldflags: Sequence[str]) -> Tuple[bool, str]:
    """Compile a minimal C snippet to verify header + library availability."""
    cmd = [gcc_bin, "-x", "c", "-", "-o", "/dev/null", *ldflags]
    try:
        proc = subprocess.run(
            cmd,
            input=code,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, "ok"
    err = proc.stderr.strip().splitlines()
    return False, err[0] if err else f"exit {proc.returncode}"


def check_techpack_make44_safe(src_dir: Path) -> Tuple[bool, str]:
    """Verify techpack/audio/Makefile does not use bare 'export' that breaks GNU Make 4.4+."""
    mk = src_dir / "techpack" / "audio" / "Makefile"
    if not mk.is_file():
        return True, "not present"
    for idx, line in enumerate(mk.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if line.strip() == "export":
            return False, f"{mk.relative_to(src_dir)}:{idx} contains bare 'export' (breaks GNU Make 4.4+)"
    return True, "no bare export statements"


def run_environment_checks(
    src_dir: Path,
    toolchains: ResolvedToolchains,
    arch: str,
    defconfig: Optional[str],
    require_toolchains: bool = True,
    require_ncurses: bool = False,
) -> Tuple[List[CheckResult], Dict[str, object]]:
    """Run all host, library, repository, and toolchain checks."""
    ctx = detect_runtime_context()
    results: List[CheckResult] = []

    # 1. Host CLI binaries.
    for tool, (required, pkg) in HOST_TOOL_SPECS.items():
        path = shutil.which(tool)
        detail = path if path else "not found in PATH"
        if tool == "make" and path:
            ver = _run_version_line([path, "--version"])
            if ver:
                detail = f"{path} ({ver})"
        results.append(CheckResult(f"tool:{tool}", bool(path), required, detail, None if path else pkg))

    # 2. Check python alias vs explicit PYTHON=python3 handling.
    py_alias = shutil.which("python")
    results.append(
        CheckResult(
            "tool:python-alias",
            True,
            False,
            py_alias if py_alias else f"no 'python' symlink (OK: build passes PYTHON={sys.executable})",
        )
    )

    # 3. Check C development headers via host gcc.
    gcc_bin = shutil.which("gcc")
    if gcc_bin:
        for name, code, ldflags, pkg, req in HEADER_PROBES:
            effective_req = req or (name == "ncurses-dev" and require_ncurses)
            ok, detail = _probe_c_header(gcc_bin, code, ldflags)
            results.append(CheckResult(f"header:{name}", ok, effective_req, detail, None if ok else pkg))
    else:
        results.append(
            CheckResult("header:probes", False, True, "skipped because host gcc is missing", "build-essential")
        )

    # 4. Repository integrity and permissions.
    make_ok, make_detail = check_techpack_make44_safe(src_dir)
    results.append(CheckResult("repo:techpack-make44", make_ok, True, make_detail))

    for rel in CRITICAL_EXEC_SCRIPTS:
        script = src_dir / rel
        if script.exists():
            is_exec = os.access(script, os.X_OK)
            results.append(
                CheckResult(
                    f"exec:{rel}",
                    is_exec,
                    True,
                    "executable" if is_exec else f"missing +x permission on {rel}",
                )
            )

    if defconfig:
        cfg_file = src_dir / "arch" / arch / "configs" / defconfig
        results.append(
            CheckResult(
                "repo:defconfig",
                cfg_file.is_file(),
                True,
                str(cfg_file) if cfg_file.is_file() else f"missing {cfg_file}",
            )
        )

    # 5. Resolved toolchains.
    results.append(
        CheckResult(
            "toolchain:clang",
            bool(toolchains.clang and toolchains.clang_version),
            require_toolchains,
            f"{toolchains.clang} ({toolchains.clang_version})" if toolchains.clang else "clang not found",
        )
    )
    results.append(
        CheckResult(
            "toolchain:cross_compile",
            bool(toolchains.cross_compile and toolchains.cross_ld_version),
            require_toolchains,
            f"{toolchains.cross_compile} ({toolchains.cross_ld_version})"
            if toolchains.cross_compile
            else "cross-compile binutils not found",
        )
    )
    results.append(
        CheckResult(
            "toolchain:lld",
            bool(toolchains.lld),
            False,
            str(toolchains.lld) if toolchains.lld else "ld.lld not found (optional unless --lld/--lto is used)",
        )
    )
    results.append(
        CheckResult(
            "toolchain:dtc",
            bool(toolchains.dtc),
            False,
            f"{toolchains.dtc} ({toolchains.dtc_version or 'executable'})"
            if toolchains.dtc
            else "no external dtc (Kbuild will build scripts/dtc/dtc)",
        )
    )

    return results, ctx


def format_env_report(
    results: Sequence[CheckResult],
    ctx: Dict[str, object],
    defconfig: Optional[str],
    toolchains: ResolvedToolchains,
) -> Tuple[str, bool]:
    """Render a concise environment check report and return (text, passed)."""
    lines: List[str] = [
        "=== MizKernel Build Environment Check ===",
        f"OS:       {ctx['os_pretty']} ({ctx['machine']})",
        f"Python:   {ctx['python_version']} ({ctx['python_executable']})",
        f"Resources:{ctx['cpu_count']} CPU(s), RAM: {ctx['mem_gib']} GiB"
        + (f", Container: {ctx['container_id']}" if ctx["container_id"] else "")
        + (", GitHub Actions: yes" if ctx["github_actions"] else ""),
        f"Defconfig:{defconfig or '(none)'}",
        f"Triple:   {toolchains.clang_triple}",
        "",
    ]

    missing_pkgs: List[str] = []
    failed_required = False
    for item in results:
        if item.ok:
            tag = "OK  "
        elif item.required:
            tag = "FAIL"
            failed_required = True
        else:
            tag = "WARN"
        lines.append(f"[{tag}] {item.name:<26} {item.detail}")
        if not item.ok and item.hint_pkg and item.hint_pkg not in missing_pkgs:
            if item.required:
                missing_pkgs.append(item.hint_pkg)

    if missing_pkgs:
        lines.extend(
            [
                "",
                "Missing required system packages. On Ubuntu/Debian, install with:",
                f"  sudo apt-get update && sudo apt-get install -y {' '.join(missing_pkgs)}",
            ]
        )

    return "\n".join(lines), not failed_required


def build_make_env(toolchains: ResolvedToolchains, build_user: Optional[str], build_host: Optional[str]) -> Dict[str, str]:
    """Build subprocess environment with toolchain bin dirs prepended to PATH."""
    env = os.environ.copy()
    for stale_key in ("BUILD_CROSS_COMPILE", "KERNEL_LLVM_BIN", "KERNEL_MAKE_ENV", "CROSS_COMPILE", "CC", "REAL_CC", "DTC_EXT"):
        env.pop(stale_key, None)
    prepend: List[str] = []
    if toolchains.clang_bin_dir:
        prepend.append(str(toolchains.clang_bin_dir))
    if toolchains.cross_bin_dir and str(toolchains.cross_bin_dir) not in prepend:
        prepend.append(str(toolchains.cross_bin_dir))

    current_path = env.get("PATH", "")
    if prepend:
        env["PATH"] = os.pathsep.join([*prepend, current_path]) if current_path else os.pathsep.join(prepend)

    if build_user:
        env["KBUILD_BUILD_USER"] = build_user
    elif "KBUILD_BUILD_USER" not in env:
        env["KBUILD_BUILD_USER"] = getpass.getuser()

    if build_host:
        env["KBUILD_BUILD_HOST"] = build_host
    elif "KBUILD_BUILD_HOST" not in env:
        env["KBUILD_BUILD_HOST"] = socket.gethostname()

    return env


def infer_project_name(src_dir: Path, arch: str, defconfig: Optional[str], explicit: Optional[str]) -> Optional[str]:
    """Infer PROJECT_NAME from explicit arg/env or defconfig project flags."""
    if explicit is not None:
        return explicit or None
    if "PROJECT_NAME" in os.environ:
        return os.environ["PROJECT_NAME"] or None
    if defconfig:
        cfg_file = src_dir / "arch" / arch / "configs" / defconfig
        if cfg_file.is_file():
            text = cfg_file.read_text(encoding="utf-8", errors="replace")
            if "CONFIG_SEC_A23_PROJECT=y" in text:
                return "a23"
    return None


def build_make_args(
    src_dir: Path,
    out_dir: Path,
    arch: str,
    subarch: str,
    jobs: int,
    toolchains: ResolvedToolchains,
    dt_overlay: bool,
    section_mismatch_warn_only: bool,
    use_lld: bool,
    project_name: Optional[str],
    localversion: Optional[str],
    kcflags: Optional[str],
    extra_make_args: Sequence[str],
    parallel: bool = True,
) -> List[str]:
    """Construct reproducible GNU Make command arguments."""
    args: List[str] = ["make"]
    if parallel:
        args.append(f"-j{jobs}")
    args.extend(
        [
            "-C",
            str(src_dir),
            f"O={out_dir}",
            f"ARCH={arch}",
            f"SUBARCH={subarch}",
            f"PYTHON={sys.executable}",
        ]
    )
    if toolchains.clang:
        args.append(f"CC={toolchains.clang}")
        args.append(f"REAL_CC={toolchains.clang}")
    if toolchains.cross_compile:
        args.append(f"CROSS_COMPILE={toolchains.cross_compile}")
    if toolchains.clang_triple:
        args.append(f"CLANG_TRIPLE={toolchains.clang_triple}")
    if toolchains.dtc:
        args.append(f"DTC_EXT={toolchains.dtc}")
    if dt_overlay:
        args.append("CONFIG_BUILD_ARM64_DT_OVERLAY=y")
    if section_mismatch_warn_only:
        args.append("CONFIG_SECTION_MISMATCH_WARN_ONLY=y")
    if use_lld:
        if not toolchains.lld:
            raise RuntimeError("LLD was requested (--lld or --lto), but ld.lld was not found.")
        args.append(f"LD={toolchains.lld}")
        for var, tool in (
            ("AR", "llvm-ar"),
            ("NM", "llvm-nm"),
            ("OBJCOPY", "llvm-objcopy"),
            ("OBJDUMP", "llvm-objdump"),
            ("READELF", "llvm-readelf"),
            ("STRIP", "llvm-strip"),
        ):
            if tool in toolchains.llvm_tools:
                args.append(f"{var}={toolchains.llvm_tools[tool]}")
    if project_name:
        args.append(f"PROJECT_NAME={project_name}")
    if localversion is not None:
        args.append(f"LOCALVERSION={localversion}")
    if kcflags:
        args.append(f"KCFLAGS={kcflags}")
    args.extend(extra_make_args)
    return args


def check_clean_srctree(src_dir: Path, out_dir: Path, mrproper_src: bool, make_env: Dict[str, str]) -> None:
    """Prevent out-of-tree Kbuild failures if srctree has leftover in-tree .config/include/config."""
    if out_dir.resolve() == src_dir.resolve():
        return
    dirty_markers = [src_dir / ".config", src_dir / "include" / "config"]
    if any(p.exists() for p in dirty_markers):
        if mrproper_src:
            print(f"[miz_build] Cleaning dirty source tree ({src_dir}) with 'make mrproper'...")
            subprocess.run(
                ["make", "-C", str(src_dir), f"PYTHON={sys.executable}", "mrproper"],
                env=make_env,
                check=True,
            )
        else:
            raise RuntimeError(
                f"Source tree '{src_dir}' is not clean (.config or include/config exists). "
                "Run 'python3 miz_build.py mrproper --in-tree' or pass '--mrproper-src'."
            )


def apply_lto_config(
    src_dir: Path,
    out_dir: Path,
    lto_mode: str,
    base_make_args: Sequence[str],
    make_env: Dict[str, str],
) -> None:
    """Update .config LTO settings via scripts/config and sync with olddefconfig."""
    cfg_script = src_dir / "scripts" / "config"
    dot_config = out_dir / ".config"
    if lto_mode == "none":
        flags = ["--disable", "LTO_CLANG", "--disable", "THINLTO", "--enable", "LTO_NONE"]
    elif lto_mode == "thin":
        flags = ["--disable", "LTO_NONE", "--enable", "LTO_CLANG", "--enable", "THINLTO"]
    elif lto_mode == "full":
        flags = ["--disable", "LTO_NONE", "--enable", "LTO_CLANG", "--disable", "THINLTO"]
    else:
        raise ValueError(f"Unsupported LTO mode: {lto_mode}")

    subprocess.run([str(cfg_script), "--file", str(dot_config), *flags], env=make_env, check=True)
    subprocess.run([*base_make_args, "olddefconfig"], env=make_env, check=True)


def run_logged(cmd: Sequence[str], env: Dict[str, str]) -> None:
    """Print and execute a build command, raising CalledProcessError on failure."""
    print(f"[miz_build] $ {shlex.join(cmd)}", flush=True)
    subprocess.run(list(cmd), env=env, check=True)


def collect_artifacts(out_dir: Path, arch: str, dist_dir: Optional[Path]) -> Dict[str, object]:
    """Summarize and optionally copy kernel build outputs into dist_dir."""
    boot_dir = out_dir / "arch" / arch / "boot"
    images = [p for p in ("Image", "Image.gz", "Image.lz4", "Image-dtb", "Image.gz-dtb", "zImage") if (boot_dir / p).is_file()]
    dtbs = sorted((boot_dir / "dts").rglob("*.dtb")) if (boot_dir / "dts").is_dir() else []
    dtbos = sorted((boot_dir / "dts").rglob("*.dtbo")) if (boot_dir / "dts").is_dir() else []
    modules = sorted(out_dir.rglob("*.ko"))
    release_file = out_dir / "include" / "config" / "kernel.release"
    kernel_release = release_file.read_text(encoding="utf-8", errors="replace").strip() if release_file.is_file() else "unknown"

    if dist_dir is not None:
        if dist_dir.exists():
            shutil.rmtree(dist_dir)
        dist_dir.mkdir(parents=True, exist_ok=True)
        for name in images:
            shutil.copy2(boot_dir / name, dist_dir / name)
        for aux in ("System.map", ".config"):
            if (out_dir / aux).is_file():
                target_name = "kernel.config" if aux == ".config" else aux
                shutil.copy2(out_dir / aux, dist_dir / target_name)
        if dtbs:
            dtb_out = dist_dir / "dtbs"
            dtb_out.mkdir(exist_ok=True)
            for dtb in dtbs:
                shutil.copy2(dtb, dtb_out / dtb.name)
        if dtbos:
            dtbo_out = dist_dir / "dtbos"
            dtbo_out.mkdir(exist_ok=True)
            for dtbo in dtbos:
                shutil.copy2(dtbo, dtbo_out / dtbo.name)
        if modules:
            mod_out = dist_dir / "modules"
            mod_out.mkdir(exist_ok=True)
            for mod in modules:
                shutil.copy2(mod, mod_out / mod.name)
        compile_h = out_dir / "include" / "generated" / "compile.h"
        info_lines = [
            f"KERNEL_RELEASE={kernel_release}",
            f"ARCH={arch}",
            f"IMAGES={', '.join(images) or 'none'}",
            f"DTB_COUNT={len(dtbs)}",
            f"DTBO_COUNT={len(dtbos)}",
            f"MODULE_COUNT={len(modules)}",
        ]
        if compile_h.is_file():
            info_lines.append("")
            info_lines.append(compile_h.read_text(encoding="utf-8", errors="replace").strip())
        (dist_dir / "build-info.txt").write_text("\n".join(info_lines) + "\n", encoding="utf-8")

    return {
        "kernel_release": kernel_release,
        "images": [str(boot_dir / img) for img in images],
        "dtb_count": len(dtbs),
        "dtbo_count": len(dtbos),
        "module_count": len(modules),
        "dist_dir": str(dist_dir) if dist_dir else None,
    }


def read_makefile_version(src_dir: Path) -> str:
    """Parse VERSION, PATCHLEVEL, SUBLEVEL, and EXTRAVERSION from top-level Makefile."""
    mk = src_dir / "Makefile"
    if not mk.is_file():
        return "unknown"
    fields: Dict[str, str] = {}
    for line in mk.read_text(encoding="utf-8", errors="replace").splitlines()[:25]:
        match = re.match(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=\s*(.*)$", line.strip())
        if match:
            fields[match.group(1)] = match.group(2).strip()
    ver = ".".join(fields[k] for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL") if k in fields and fields[k])
    extra = fields.get("EXTRAVERSION", "")
    return f"{ver}{extra}" if ver else "unknown"


def read_defconfig_localversion(src_dir: Path, arch: str, defconfig: Optional[str]) -> str:
    """Extract CONFIG_LOCALVERSION from the resolved defconfig if set."""
    if not defconfig:
        return ""
    cfg_path = src_dir / "arch" / arch / "configs" / defconfig
    if not cfg_path.is_file():
        return ""
    for line in cfg_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r'^CONFIG_LOCALVERSION="([^"]*)"$', line.strip())
        if match:
            return match.group(1)
    return ""


def _run_git_stdout(src_dir: Path, args: Sequence[str]) -> str:
    """Run a git command in src_dir and return stripped stdout or empty string."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(src_dir), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def resolve_git_context(src_dir: Path) -> Dict[str, object]:
    """Resolve commit SHA, ref, branch/tag name, build count, and tag context from CI env or git."""
    git_sha = os.environ.get("GITHUB_SHA") or _run_git_stdout(src_dir, ["rev-parse", "HEAD"]) or "unknown"
    short_sha = git_sha[:8] if git_sha != "unknown" else "unknown"
    git_ref = os.environ.get("GITHUB_REF") or _run_git_stdout(src_dir, ["symbolic-ref", "-q", "HEAD"])
    ref_name = os.environ.get("GITHUB_REF_NAME") or ""
    if not ref_name:
        ref_name = _run_git_stdout(src_dir, ["rev-parse", "--abbrev-ref", "HEAD"]) or "detached"
    ref_type = os.environ.get("GITHUB_REF_TYPE") or ""
    is_tag = ref_type == "tag" or git_ref.startswith("refs/tags/")
    commit_count = _run_git_stdout(src_dir, ["rev-list", "--count", "HEAD"])
    dynamic_version = (
        _run_git_stdout(src_dir, ["describe", "--tags", "--always", "--exclude", "ci-*"])
        or _run_git_stdout(src_dir, ["describe", "--tags", "--always"])
        or short_sha
    )
    target_ref = f"refs/tags/{ref_name}" if is_tag else "HEAD"
    prev_ref = f"{target_ref}^" if is_tag else target_ref
    previous_tag = (
        _run_git_stdout(src_dir, ["describe", "--tags", "--abbrev=0", "--exclude", "ci-*", prev_ref])
        or _run_git_stdout(src_dir, ["describe", "--tags", "--abbrev=0", prev_ref])
    )
    if previous_tag == ref_name:
        previous_tag = ""
    return {
        "git_sha": git_sha,
        "short_sha": short_sha,
        "git_ref": git_ref,
        "ref_name": ref_name,
        "is_tag": is_tag,
        "commit_count": commit_count,
        "dynamic_version": dynamic_version,
        "previous_tag": previous_tag,
    }


def sanitize_tag_component(value: str) -> str:
    """Normalize a string into a safe Git tag / filename component."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-")
    return cleaned or "snapshot"


def resolve_release_metadata(
    src_dir: Path,
    arch: str,
    defconfig: Optional[str],
    localversion_override: Optional[str],
    env_keys: Sequence[str],
    event_name: str,
    publish_mode: str,
    prerelease_mode: str,
    release_tag_override: Optional[str],
    release_name_override: Optional[str],
    strict_env_keys: bool,
) -> Tuple[Dict[str, object], List[str]]:
    """Resolve dynamic release metadata and verify presence of required environment keys."""
    kernel_version = read_makefile_version(src_dir)
    localversion = (
        localversion_override
        if localversion_override is not None and localversion_override != ""
        else read_defconfig_localversion(src_dir, arch, defconfig)
    )
    git_ctx = resolve_git_context(src_dir)
    is_tag = bool(git_ctx["is_tag"])
    ref_name = str(git_ctx["ref_name"])
    short_sha = str(git_ctx["short_sha"])

    key_status: Dict[str, bool] = {}
    missing_keys: List[str] = []
    for key in env_keys:
        present = bool(os.environ.get(key, "").strip())
        key_status[key] = present
        if not present:
            missing_keys.append(key)
    env_keys_present = len(missing_keys) == 0

    if prerelease_mode == "true":
        is_prerelease = True
    elif prerelease_mode == "false":
        is_prerelease = False
    elif is_tag:
        is_prerelease = bool(re.search(r"(alpha|beta|rc|pre|dev|nightly|snapshot|test)", ref_name, re.IGNORECASE))
    else:
        # Branch pushes and manual dispatches default to pre-release builds.
        is_prerelease = True

    if release_tag_override:
        release_tag = release_tag_override.strip()
    elif is_tag:
        release_tag = ref_name
    else:
        ref_part = sanitize_tag_component(ref_name)
        release_tag = f"ci-{sanitize_tag_component(kernel_version)}-{ref_part}-{short_sha}"

    repo_label = (os.environ.get("GITHUB_REPOSITORY") or src_dir.name).split("/")[-1]
    if release_name_override:
        release_name = release_name_override.strip()
    elif is_tag:
        release_name = f"{repo_label} {ref_name}"
    else:
        release_name = f"{repo_label} {kernel_version}{localversion} ({short_sha})"

    if event_name == "pull_request":
        should_release = False
        release_reason = "pull_request events do not publish GitHub Releases"
    elif publish_mode == "false":
        should_release = False
        release_reason = "release publishing disabled via publish_release=false"
    elif not env_keys_present:
        should_release = False
        release_reason = f"missing environment key(s): {', '.join(missing_keys)}"
        if strict_env_keys or publish_mode == "true":
            raise RuntimeError(f"Release requested but required environment key(s) are missing: {', '.join(missing_keys)}")
    else:
        should_release = True
        release_reason = "tag push release" if (is_tag and not is_prerelease) else "pre-release push enabled"

    build_number = os.environ.get("GITHUB_RUN_NUMBER") or str(git_ctx["commit_count"] or "1")
    metadata: Dict[str, object] = {
        "repo": os.environ.get("GITHUB_REPOSITORY") or src_dir.name,
        "event_name": event_name,
        "arch": arch,
        "defconfig": defconfig or "",
        "kernel_version": kernel_version,
        "localversion": localversion,
        "build_number": build_number,
        "dynamic_version": git_ctx["dynamic_version"],
        "previous_tag": git_ctx["previous_tag"],
        "git_sha": git_ctx["git_sha"],
        "short_sha": short_sha,
        "git_ref": git_ctx["git_ref"],
        "ref_name": ref_name,
        "is_tag": is_tag,
        "env_keys_checked": list(env_keys),
        "env_keys": key_status,
        "env_keys_present": env_keys_present,
        "prerelease": is_prerelease,
        "should_release": should_release,
        "release_reason": release_reason,
        "release_tag": release_tag,
        "release_name": release_name,
    }
    return metadata, missing_keys


def write_github_output(output_path: Path, metadata: Dict[str, object]) -> None:
    """Write resolved metadata key=value pairs to a GITHUB_OUTPUT file."""
    flat: Dict[str, str] = {}
    for key in (
        "arch",
        "defconfig",
        "kernel_version",
        "localversion",
        "build_number",
        "dynamic_version",
        "previous_tag",
        "git_sha",
        "short_sha",
        "git_ref",
        "ref_name",
        "release_tag",
        "release_name",
        "release_reason",
    ):
        flat[key] = str(metadata.get(key, ""))
    for bool_key in ("is_tag", "env_keys_present", "prerelease", "should_release"):
        flat[bool_key] = "true" if metadata.get(bool_key) else "false"
    for env_key, present in dict(metadata.get("env_keys", {})).items():
        flat[f"has_{env_key.lower()}"] = "true" if present else "false"

    lines = [f"{k}={v.replace(chr(10), ' ')}" for k, v in flat.items()]
    with output_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _human_size(num_bytes: int) -> str:
    """Format byte size using human-readable binary units."""
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024.0 or unit == "GiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{num_bytes} B"


def _describe_release_asset(filename: str) -> str:
    """Return a descriptive label for a generated kernel release asset."""
    if filename.endswith(".zip"):
        if "-AK3-" in filename or filename.startswith("AnyKernel3"):
            return "Flashable AnyKernel3 Package"
        return "Audit Kernel Bundle (Images, DTBs, DTBOs, Modules, Config)"
    if filename == "Image.gz":
        return "Compressed ARM64 Kernel Image"
    if filename == "Image":
        return "Uncompressed ARM64 Kernel Image"
    if filename == "build-info.txt":
        return "Build Telemetry & Compiler Metadata"
    if filename == "SHA256SUMS.txt":
        return "SHA-256 Verification Checksums"
    if filename.endswith(".sha256"):
        return "SHA-256 Sidecar Checksum"
    return "Kernel Release Asset"


def write_release_checksums(release_dir: Path) -> List[str]:
    """Generate and write sorted SHA-256 checksums for all assets in release_dir."""
    asset_files = sorted(p for p in release_dir.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt")
    checksum_lines = [f"{_sha256_file(p)}  {p.name}" for p in asset_files]
    (release_dir / "SHA256SUMS.txt").write_text(
        ("\n".join(checksum_lines) + "\n") if checksum_lines else "",
        encoding="utf-8",
    )
    return checksum_lines


def generate_release_report(
    src_dir: Path,
    release_dir: Path,
    arch: str,
    defconfig: Optional[str],
    release_tag: Optional[str],
    prerelease: bool,
    build_number: Optional[str],
    output_path: Optional[Path] = None,
    step_summary_path: Optional[Path] = None,
) -> str:
    """Build a Markdown changelog, asset table, and SHA-256 verification report."""
    git_ctx = resolve_git_context(src_dir)
    repo_slug = os.environ.get("GITHUB_REPOSITORY", "")
    repo_label = (repo_slug or src_dir.name).split("/")[-1]
    prev_tag = str(git_ctx["previous_tag"] or "")
    target_ref = str(git_ctx["git_sha"]) if git_ctx["git_sha"] != "unknown" else "HEAD"
    effective_tag = release_tag or str(git_ctx["ref_name"])
    effective_build = build_number or os.environ.get("GITHUB_RUN_NUMBER") or str(git_ctx["commit_count"] or "1")

    build_info_text = ""
    build_info_file = release_dir / "build-info.txt"
    if build_info_file.is_file():
        build_info_text = build_info_file.read_text(encoding="utf-8", errors="replace")

    kernel_release = read_makefile_version(src_dir) + read_defconfig_localversion(src_dir, arch, defconfig)
    compiler_str = ""
    for line in build_info_text.splitlines():
        if line.startswith("KERNEL_RELEASE="):
            kernel_release = line.split("=", 1)[1].strip()
        elif "LINUX_COMPILER" in line:
            compiler_str = line.split("LINUX_COMPILER", 1)[1].strip().strip('"')

    # Collect git commits since previous tag (or recent commits).
    pretty_fmt = (
        f"* [`%h`](https://github.com/{repo_slug}/commit/%H) - %s (%an)"
        if repo_slug
        else "* `%h` - %s (%an)"
    )
    if prev_tag and prev_tag != effective_tag:
        patch_header = f"**Changes in `{effective_tag}` (since `{prev_tag}`):**"
        commits_raw = _run_git_stdout(src_dir, ["log", f"{prev_tag}..{target_ref}", "-n", "30", f"--pretty=format:{pretty_fmt}"])
        diff_line = f"**Full Diff:** https://github.com/{repo_slug}/compare/{prev_tag}...{target_ref}" if repo_slug else ""
    else:
        patch_header = f"**Recent Commits for `{effective_tag}`:**"
        commits_raw = _run_git_stdout(src_dir, ["log", target_ref, "-n", "25", f"--pretty=format:{pretty_fmt}"])
        diff_line = ""

    if not commits_raw:
        commits_raw = _run_git_stdout(src_dir, ["log", "-1", f"--pretty=format:{pretty_fmt}"]) or "* No commit history available."

    # Ensure SHA256SUMS.txt exists and read checksums.
    sums_file = release_dir / "SHA256SUMS.txt"
    if not sums_file.is_file():
        write_release_checksums(release_dir)
    asset_files = sorted(p for p in release_dir.iterdir() if p.is_file())
    checksum_block = sums_file.read_text(encoding="utf-8", errors="replace").strip()

    kind_badge = "Pre-release" if prerelease else "Release"
    lines: List[str] = [
        f"## {repo_label} {kind_badge} Notes",
        f"**Kernel Release:** `{kernel_release}` | **Build:** `#{effective_build}` | **Revision:** `{git_ctx['dynamic_version']}`",
        f"**Arch:** `{arch}` | **Defconfig:** `{defconfig or 'auto'}`",
    ]
    if compiler_str:
        lines.append(f"**Toolchain:** `{compiler_str}`")
    lines.extend(["", "---", "", "### Applied Patches & Commits", patch_header, "", commits_raw])
    if diff_line:
        lines.extend(["", diff_line])

    lines.extend(
        [
            "",
            "---",
            "",
            "### Available Packages & Assets",
            "| Package | File | Size |",
            "| :--- | :--- | :--- |",
        ]
    )
    for asset in asset_files:
        lines.append(f"| {_describe_release_asset(asset.name)} | `{asset.name}` | {_human_size(asset.stat().st_size)} |")

    lines.extend(
        [
            "",
            "### Verification (SHA-256 Checksums)",
            "```text",
            checksum_block,
            "```",
        ]
    )
    report_text = "\n".join(lines) + "\n"

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_text, encoding="utf-8")
    if step_summary_path is not None:
        with step_summary_path.open("a", encoding="utf-8") as fh:
            fh.write(report_text + "\n")
    return report_text


def check_ksu_presence(src_dir: Path, arch: str, defconfig: Optional[str]) -> Dict[str, object]:
    """Inspect repository tree, Kbuild wiring, defconfig, and hooks for KernelSU presence."""
    # 1. Check .gitmodules for any KSU/SukiSU submodule entries.
    ksu_submodules = [
        {"name": name, "path": rel_path.as_posix(), "url": url}
        for name, rel_path, url in parse_gitmodules(src_dir)
        if re.search(r"(kernelsu|sukisu|\bksu\b)", f"{name} {rel_path} {url}", re.IGNORECASE)
    ]

    # 2. Discover KernelSU source directories / symlinks in common kernel locations.
    candidate_paths: List[Path] = [
        src_dir / "drivers" / "kernelsu",
        src_dir / "KernelSU",
        src_dir / "KernelSU-Next",
        src_dir / "SukiSU",
    ]
    drivers_dir = src_dir / "drivers"
    if drivers_dir.is_dir():
        for entry in sorted(drivers_dir.iterdir()):
            if "ksu" in entry.name.lower() and entry not in candidate_paths:
                candidate_paths.append(entry)

    detected_sources: List[Dict[str, object]] = []
    for cand in candidate_paths:
        if not (cand.exists() or cand.is_symlink()):
            continue
        resolved = cand.resolve() if cand.exists() else None
        has_kbuild = bool(
            resolved
            and resolved.is_dir()
            and ((resolved / "Kconfig").is_file() or (resolved / "kernel" / "Kconfig").is_file())
            and ((resolved / "Makefile").is_file() or (resolved / "kernel" / "Makefile").is_file())
        )
        detected_sources.append(
            {
                "path": cand.relative_to(src_dir).as_posix(),
                "is_symlink": cand.is_symlink(),
                "exists": cand.exists(),
                "has_kbuild_files": has_kbuild,
            }
        )

    valid_sources = [s for s in detected_sources if s["exists"] and s["has_kbuild_files"]]
    source_present = len(valid_sources) > 0
    primary_source_path = str(valid_sources[0]["path"]) if valid_sources else (str(detected_sources[0]["path"]) if detected_sources else "")

    # 3. Check drivers/Kconfig and drivers/Makefile wiring.
    drivers_kconfig = src_dir / "drivers" / "Kconfig"
    drivers_makefile = src_dir / "drivers" / "Makefile"
    kconfig_wired = bool(
        drivers_kconfig.is_file()
        and re.search(r"kernelsu|KSU", drivers_kconfig.read_text(encoding="utf-8", errors="replace"), re.IGNORECASE)
    )
    makefile_wired = bool(
        drivers_makefile.is_file()
        and re.search(r"kernelsu|CONFIG_KSU", drivers_makefile.read_text(encoding="utf-8", errors="replace"), re.IGNORECASE)
    )
    kbuild_wired = kconfig_wired and makefile_wired

    # 4. Check resolved defconfig for CONFIG_KSU* and CONFIG_KPROBES.
    defconfig_ksu_flags: List[str] = []
    kprobes_enabled = False
    if defconfig:
        cfg_file = src_dir / "arch" / arch / "configs" / defconfig
        if cfg_file.is_file():
            for line in cfg_file.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped.startswith("CONFIG_KSU"):
                    defconfig_ksu_flags.append(stripped)
                elif stripped == "CONFIG_KPROBES=y":
                    kprobes_enabled = True
    defconfig_enabled = any(flag == "CONFIG_KSU=y" for flag in defconfig_ksu_flags)

    # 5. Scan standard kernel hook points for KSU integration.
    hook_targets = (
        "fs/exec.c",
        "fs/open.c",
        "fs/read_write.c",
        "fs/stat.c",
        "fs/devpts/inode.c",
        "drivers/input/input.c",
    )
    hook_files: List[str] = []
    for rel in hook_targets:
        fpath = src_dir / rel
        if fpath.is_file():
            text = fpath.read_text(encoding="utf-8", errors="replace")
            if re.search(r"\bCONFIG_KSU\b|ksu_handle_", text):
                hook_files.append(rel)

    if source_present and kbuild_wired and defconfig_enabled:
        ksu_status = "complete"
    elif source_present or kconfig_wired or makefile_wired or defconfig_enabled or hook_files or ksu_submodules:
        ksu_status = "partial"
    else:
        ksu_status = "absent"

    return {
        "defconfig": defconfig or "",
        "ksu_present": ksu_status == "complete",
        "ksu_status": ksu_status,
        "ksu_source_present": source_present,
        "ksu_source_path": primary_source_path,
        "detected_sources": detected_sources,
        "ksu_submodules": ksu_submodules,
        "kconfig_wired": kconfig_wired,
        "makefile_wired": makefile_wired,
        "kbuild_wired": kbuild_wired,
        "defconfig_enabled": defconfig_enabled,
        "defconfig_ksu_flags": defconfig_ksu_flags,
        "kprobes_enabled": kprobes_enabled,
        "ksu_hook_files": hook_files,
        "ksu_hook_count": len(hook_files),
    }


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_release_assets(
    src_dir: Path,
    out_dir: Path,
    dist_dir: Path,
    release_dir: Path,
    release_notes_path: Optional[Path],
    arch: str,
    defconfig: Optional[str],
    summary: Dict[str, object],
) -> Dict[str, object]:
    """Create compressed release archive, standalone kernel image, checksums, and notes."""
    if release_dir.exists():
        shutil.rmtree(release_dir)
    release_dir.mkdir(parents=True, exist_ok=True)

    git_ctx = resolve_git_context(src_dir)
    short_sha = str(git_ctx["short_sha"])
    kernel_release = sanitize_tag_component(str(summary.get("kernel_release") or "unknown"))
    repo_label = sanitize_tag_component((os.environ.get("GITHUB_REPOSITORY") or src_dir.name).split("/")[-1])
    zip_name = f"{repo_label}-{kernel_release}-{short_sha}.zip"
    zip_path = release_dir / zip_name

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(dist_dir.rglob("*")):
            if item.is_file():
                zf.write(item, arcname=item.relative_to(dist_dir).as_posix())

    image_name = "Image.gz" if (dist_dir / "Image.gz").is_file() else ("Image" if (dist_dir / "Image").is_file() else None)
    for fname in ([image_name] if image_name else []) + ["build-info.txt"]:
        cand = dist_dir / fname
        if cand.is_file():
            shutil.copy2(cand, release_dir / fname)

    checksum_lines = write_release_checksums(release_dir)

    if release_notes_path is not None:
        release_notes_path.parent.mkdir(parents=True, exist_ok=True)
        compile_h = out_dir / "include" / "generated" / "compile.h"
        compiler_line = ""
        if compile_h.is_file():
            for line in compile_h.read_text(encoding="utf-8", errors="replace").splitlines():
                if "LINUX_COMPILER" in line:
                    compiler_line = line.split("LINUX_COMPILER", 1)[1].strip().strip('"')
                    break
        notes = [
            f"### {repo_label} Build Metadata",
            f"- **Kernel Release:** `{summary.get('kernel_release')}`",
            f"- **Architecture:** `{arch}`",
            f"- **Defconfig:** `{defconfig or 'unknown'}`",
            f"- **Commit:** `{git_ctx['git_sha']}`",
            f"- **DTBs / DTBOs / Modules:** `{summary.get('dtb_count', 0)}` / `{summary.get('dtbo_count', 0)}` / `{summary.get('module_count', 0)}`",
        ]
        if compiler_line:
            notes.append(f"- **Compiler:** `{compiler_line}`")
        notes.extend(["", "### SHA-256 Checksums", "```", *checksum_lines, "```"])
        release_notes_path.write_text("\n".join(notes) + "\n", encoding="utf-8")

    return {
        "release_dir": str(release_dir),
        "archive": str(zip_path),
        "assets": [p.name for p in sorted(release_dir.iterdir()) if p.is_file()],
        "release_notes": str(release_notes_path) if release_notes_path else None,
    }


def add_common_options(parser: argparse.ArgumentParser) -> None:
    """Register shared path, toolchain, and Kbuild configuration arguments."""
    default_root = Path(__file__).resolve().parent
    parser.add_argument("--src-dir", type=Path, default=default_root, help="Kernel source root directory.")
    parser.add_argument(
        "--out",
        "--out-dir",
        dest="out_dir",
        type=Path,
        default=Path(os.environ.get("OUT_DIR") or os.environ.get("KBUILD_OUTPUT") or (default_root / "out")),
        help="Build output directory (O=).",
    )
    parser.add_argument("--arch", default=os.environ.get("ARCH", "arm64"), help="Target ARCH (default: env ARCH or arm64).")
    parser.add_argument("--subarch", default=os.environ.get("SUBARCH"), help="Target SUBARCH (default: ARCH).")
    parser.add_argument(
        "--defconfig",
        default=os.environ.get("DEFCONFIG") or os.environ.get("KERNEL_DEFCONFIG"),
        help="Defconfig path under arch/<arch>/configs/ (auto-discovered if omitted).",
    )
    parser.add_argument(
        "--toolchain-dir",
        type=Path,
        default=Path(os.environ.get("TOOLCHAIN_DIR", default_root / "toolchain")),
        help="Base directory searched for prebuilt toolchains.",
    )
    parser.add_argument("--toolchain", dest="preferred_toolchain", help="Preferred toolchain folder name under --toolchain-dir.")
    parser.add_argument("--clang", default=None, help="Path to clang executable.")
    parser.add_argument("--cross-compile", default=None, help="CROSS_COMPILE binary prefix.")
    parser.add_argument("--clang-triple", default=os.environ.get("CLANG_TRIPLE"), help="CLANG_TRIPLE value.")
    parser.add_argument("--dtc", default=None, help="Path to external dtc binary.")
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=int(os.environ["JOBS"]) if os.environ.get("JOBS") else (os.cpu_count() or 1),
        help="Parallel make jobs (default: detected CPU count).",
    )
    parser.add_argument("--project-name", default=None, help="Override PROJECT_NAME passed to Make.")
    parser.add_argument("--build-user", default=os.environ.get("KBUILD_BUILD_USER"), help="Override KBUILD_BUILD_USER.")
    parser.add_argument("--build-host", default=os.environ.get("KBUILD_BUILD_HOST"), help="Override KBUILD_BUILD_HOST.")
    parser.add_argument("--localversion", default=os.environ.get("LOCALVERSION"), help="Override LOCALVERSION.")
    parser.add_argument("--kcflags", default=os.environ.get("KCFLAGS"), help="Additional KCFLAGS passed to Make.")
    parser.add_argument(
        "--lld",
        choices=("auto", "on", "off"),
        default=os.environ.get("USE_LLD", "auto"),
        help="Use ld.lld linker ('auto' enables LLD only when LTO requires it).",
    )
    parser.add_argument(
        "--lto",
        choices=("keep", "none", "thin", "full"),
        default=os.environ.get("LTO", "keep"),
        help="Configure Clang LTO mode after defconfig ('keep' preserves defconfig setting).",
    )
    parser.add_argument("--no-dt-overlay", action="store_true", help="Do not force CONFIG_BUILD_ARM64_DT_OVERLAY=y.")
    parser.add_argument(
        "--strict-section-mismatch",
        action="store_true",
        help="Do not pass CONFIG_SECTION_MISMATCH_WARN_ONLY=y.",
    )
    parser.add_argument(
        "--distrobox",
        default=os.environ.get("MIZ_DISTROBOX"),
        help="Optional distrobox container name to enter before running.",
    )
    parser.add_argument(
        "--make-arg",
        action="append",
        default=[],
        help="Extra KEY=VAL or target argument forwarded to Make (repeatable).",
    )


def build_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser with subcommands for check, build, kconfig, and cleanup."""
    parser = argparse.ArgumentParser(
        prog="miz_build.py",
        description="MizKernel central build orchestrator and Ubuntu 26.04 / CI environment checker.",
    )
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="Verify host OS, packages, headers, scripts, and toolchains.")
    add_common_options(p_check)
    p_check.add_argument("--json", action="store_true", help="Output environment check report as JSON.")
    p_check.add_argument("--no-require-toolchains", action="store_true", help="Do not fail if toolchains are not downloaded yet.")
    p_check.add_argument("--require-ncurses", action="store_true", help="Require ncurses development headers (menuconfig).")

    p_fetch = sub.add_parser("fetch-toolchains", help="Fetch missing toolchains defined in .gitmodules.")
    add_common_options(p_fetch)
    p_fetch.add_argument("--name", action="append", default=[], help="Specific toolchain name/path from .gitmodules (repeatable).")
    p_fetch.add_argument("--toolchain-url", action="append", default=[], help="Override or add <name>=<git_url> (repeatable).")
    p_fetch.add_argument("--force", action="store_true", help="Re-clone even if target directory already exists.")
    p_fetch.add_argument("--all", dest="fetch_all", action="store_true", help="Clone all reachable toolchain entries in .gitmodules.")

    p_build = sub.add_parser("build", help="Check environment, configure, and build the kernel.")
    add_common_options(p_build)
    p_build.add_argument("--clean", action="store_true", help="Remove output directory before building.")
    p_build.add_argument("--no-defconfig", action="store_true", help="Skip defconfig if out/.config already exists.")
    p_build.add_argument("--skip-env-check", action="store_true", help="Skip pre-build environment verification.")
    p_build.add_argument("--mrproper-src", action="store_true", help="Run 'make mrproper' on source tree if dirty.")
    p_build.add_argument("--auto-fetch-toolchains", action="store_true", help="Fetch missing toolchains from .gitmodules automatically.")
    p_build.add_argument("--target", action="append", default=[], help="Specific Make targets (default: full build).")
    p_build.add_argument("--dist-dir", type=Path, help="Copy built Image/DTBs/DTBOs/modules into this directory.")
    p_build.add_argument("--release-dir", type=Path, help="Package release zip, standalone image, and SHA256SUMS.txt into this directory.")
    p_build.add_argument("--release-notes", type=Path, help="Write Markdown release summary and checksums to this file.")

    p_meta = sub.add_parser("metadata", help="Resolve dynamic kernel/git release metadata and verify env keys.")
    add_common_options(p_meta)
    p_meta.add_argument(
        "--check-env-key",
        action="append",
        default=[],
        help="Environment variable/secret name to verify is non-empty (repeatable).",
    )
    p_meta.add_argument(
        "--strict-env-keys",
        action="store_true",
        help="Exit non-zero if any checked environment key is missing.",
    )
    p_meta.add_argument(
        "--event-name",
        default=os.environ.get("GITHUB_EVENT_NAME", "local"),
        help="Trigger event name (default: GITHUB_EVENT_NAME or 'local').",
    )
    p_meta.add_argument(
        "--publish-release",
        choices=("auto", "true", "false"),
        default="auto",
        help="Release publishing policy ('auto' publishes when non-PR and env keys are present).",
    )
    p_meta.add_argument(
        "--prerelease",
        choices=("auto", "true", "false"),
        default="auto",
        help="Prerelease classification ('auto' marks branch/dispatches and pre-tags as prerelease).",
    )
    p_meta.add_argument("--release-tag", default=None, help="Override resolved release tag.")
    p_meta.add_argument("--release-name", default=None, help="Override resolved release title.")
    p_meta.add_argument("--github-output", type=Path, help="Append resolved key=value pairs to GITHUB_OUTPUT file.")
    p_meta.add_argument("--step-summary", type=Path, help="Append Markdown summary to GITHUB_STEP_SUMMARY file.")
    p_meta.add_argument("--json", action="store_true", help="Print resolved metadata as JSON.")

    p_report = sub.add_parser("report", help="Generate release notes, patch list, and SHA-256 checksum report.")
    add_common_options(p_report)
    p_report.add_argument("--release-dir", type=Path, required=True, help="Directory containing packaged release assets.")
    p_report.add_argument("--release-tag", default=None, help="Release tag name used in changelog headings.")
    p_report.add_argument("--prerelease", choices=("true", "false"), default="true", help="Whether release is a pre-release.")
    p_report.add_argument("--build-number", default=None, help="Build number displayed in release header.")
    p_report.add_argument("--output", type=Path, help="Write generated Markdown report to this file.")
    p_report.add_argument("--step-summary", type=Path, help="Append generated Markdown report to GITHUB_STEP_SUMMARY.")

    p_sums = sub.add_parser("checksums", help="Write or refresh SHA256SUMS.txt for all files in a release directory.")
    p_sums.add_argument("--release-dir", type=Path, required=True, help="Directory containing packaged release assets.")
    p_sums.add_argument("--distrobox", default=os.environ.get("MIZ_DISTROBOX"), help="Optional distrobox container name.")

    p_ksu = sub.add_parser("check-ksu", help="Inspect KernelSU source, Kbuild wiring, defconfig, and kernel hook presence.")
    add_common_options(p_ksu)
    p_ksu.add_argument("--fail-on-missing", action="store_true", help="Exit non-zero if KernelSU is not fully integrated.")
    p_ksu.add_argument("--require-hooks", action="store_true", help="Also require manual hooks or CONFIG_KPROBES=y when failing on missing.")
    p_ksu.add_argument("--github-output", type=Path, help="Append KSU presence outputs to GITHUB_OUTPUT.")
    p_ksu.add_argument("--step-summary", type=Path, help="Append KSU Markdown check table to GITHUB_STEP_SUMMARY.")
    p_ksu.add_argument("--json", action="store_true", help="Print KSU presence report as JSON.")

    for kcmd, help_text in (
        ("defconfig", "Generate .config in the output directory from the selected defconfig."),
        ("menuconfig", "Run interactive Kconfig menuconfig inside the output directory."),
        ("nconfig", "Run interactive Kconfig nconfig inside the output directory."),
        ("olddefconfig", "Refresh out/.config with olddefconfig."),
        ("savedefconfig", "Generate minimal out/defconfig."),
    ):
        pk = sub.add_parser(kcmd, help=help_text)
        add_common_options(pk)
        pk.add_argument("--no-defconfig", action="store_true", help="Do not initialize out/.config from defconfig first.")
        pk.add_argument("--mrproper-src", action="store_true", help="Run 'make mrproper' on source tree if dirty.")
        if kcmd == "savedefconfig":
            pk.add_argument("--update-defconfig", action="store_true", help="Copy generated out/defconfig back to selected defconfig.")

    for ccmd, help_text in (
        ("clean", "Run 'make clean' in the output directory."),
        ("mrproper", "Run 'make mrproper' in the output directory (or source tree with --in-tree)."),
    ):
        pc = sub.add_parser(ccmd, help=help_text)
        add_common_options(pc)
        if ccmd == "mrproper":
            pc.add_argument("--in-tree", action="store_true", help="Clean the source tree itself instead of --out.")

    return parser


def _resolve_from_args(args: argparse.Namespace) -> Tuple[Path, Path, str, Optional[str], ResolvedToolchains]:
    """Resolve source/output dirs, defconfig, and toolchains from parsed CLI args."""
    src_dir = args.src_dir.resolve()
    out_dir = args.out_dir if args.out_dir.is_absolute() else (src_dir / args.out_dir)
    out_dir = out_dir.resolve()
    subarch = args.subarch or args.arch

    defconfig: Optional[str] = None
    try:
        defconfig = resolve_defconfig(src_dir, args.arch, args.defconfig)
    except FileNotFoundError:
        if args.defconfig:
            raise

    toolchains = resolve_toolchains(
        src_dir=src_dir,
        toolchain_dir=args.toolchain_dir if args.toolchain_dir.is_absolute() else (src_dir / args.toolchain_dir),
        arch=args.arch,
        explicit_clang=args.clang,
        explicit_cross=args.cross_compile,
        explicit_triple=args.clang_triple,
        explicit_dtc=args.dtc,
        preferred_toolchain=args.preferred_toolchain,
    )
    return src_dir, out_dir, subarch, defconfig, toolchains


def handle_check(args: argparse.Namespace) -> int:
    """Execute the 'check' subcommand."""
    src_dir, _, _, defconfig, toolchains = _resolve_from_args(args)
    results, ctx = run_environment_checks(
        src_dir=src_dir,
        toolchains=toolchains,
        arch=args.arch,
        defconfig=defconfig,
        require_toolchains=not args.no_require_toolchains,
        require_ncurses=args.require_ncurses,
    )
    if args.json:
        payload = {
            "context": ctx,
            "defconfig": defconfig,
            "toolchains": {
                "clang": str(toolchains.clang) if toolchains.clang else None,
                "clang_version": toolchains.clang_version,
                "cross_compile": toolchains.cross_compile,
                "cross_ld_version": toolchains.cross_ld_version,
                "clang_triple": toolchains.clang_triple,
                "lld": str(toolchains.lld) if toolchains.lld else None,
                "dtc": str(toolchains.dtc) if toolchains.dtc else None,
            },
            "checks": [dataclasses.asdict(r) for r in results],
            "passed": all(r.ok or not r.required for r in results),
        }
        print(json.dumps(payload, indent=2))
        return 0 if payload["passed"] else 1

    report, passed = format_env_report(results, ctx, defconfig, toolchains)
    print(report)
    return 0 if passed else 1


def handle_build(args: argparse.Namespace) -> int:
    """Execute the 'build' subcommand."""
    src_dir, out_dir, subarch, defconfig, toolchains = _resolve_from_args(args)
    if args.auto_fetch_toolchains and (not toolchains.clang or not toolchains.cross_compile):
        tc_dir = args.toolchain_dir if args.toolchain_dir.is_absolute() else (src_dir / args.toolchain_dir)
        rc = fetch_toolchains(src_dir, tc_dir, args.arch, [], [], force=False)
        if rc != 0:
            return rc
        src_dir, out_dir, subarch, defconfig, toolchains = _resolve_from_args(args)

    if not defconfig:
        raise FileNotFoundError(f"Could not resolve a defconfig under {src_dir / 'arch' / args.arch / 'configs'}.")

    if not args.skip_env_check:
        results, ctx = run_environment_checks(
            src_dir=src_dir,
            toolchains=toolchains,
            arch=args.arch,
            defconfig=defconfig,
            require_toolchains=True,
            require_ncurses=False,
        )
        report, passed = format_env_report(results, ctx, defconfig, toolchains)
        print(report)
        if not passed:
            return 1

    use_lld = args.lld == "on" or (args.lld == "auto" and args.lto in ("thin", "full"))
    if args.lto in ("thin", "full") and args.lld == "off":
        raise RuntimeError(f"--lto {args.lto} requires LLD; cannot combine with --lld off.")

    make_env = build_make_env(toolchains, args.build_user, args.build_host)
    check_clean_srctree(src_dir, out_dir, args.mrproper_src, make_env)

    if args.clean and out_dir.exists():
        print(f"[miz_build] Removing output directory: {out_dir}")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    project_name = infer_project_name(src_dir, args.arch, defconfig, args.project_name)
    make_args = build_make_args(
        src_dir=src_dir,
        out_dir=out_dir,
        arch=args.arch,
        subarch=subarch,
        jobs=args.jobs,
        toolchains=toolchains,
        dt_overlay=not args.no_dt_overlay,
        section_mismatch_warn_only=not args.strict_section_mismatch,
        use_lld=use_lld,
        project_name=project_name,
        localversion=args.localversion,
        kcflags=args.kcflags,
        extra_make_args=args.make_arg,
    )

    started = time.monotonic()
    dot_config = out_dir / ".config"
    if not args.no_defconfig or not dot_config.is_file():
        run_logged([*make_args, defconfig], make_env)

    if args.lto != "keep":
        apply_lto_config(src_dir, out_dir, args.lto, make_args, make_env)

    run_logged([*make_args, *args.target], make_env)
    elapsed = time.monotonic() - started

    dist_dir = None
    if args.dist_dir:
        dist_dir = args.dist_dir if args.dist_dir.is_absolute() else (src_dir / args.dist_dir)
    release_dir = None
    if args.release_dir:
        release_dir = args.release_dir if args.release_dir.is_absolute() else (src_dir / args.release_dir)
    release_notes = None
    if args.release_notes:
        release_notes = args.release_notes if args.release_notes.is_absolute() else (src_dir / args.release_notes)

    temp_dist_cm = None
    effective_dist = dist_dir
    if release_dir is not None and effective_dist is None:
        temp_dist_cm = tempfile.TemporaryDirectory(prefix="miz-dist-")
        effective_dist = Path(temp_dist_cm.name)

    try:
        summary = collect_artifacts(out_dir, args.arch, effective_dist)
        release_info: Optional[Dict[str, object]] = None
        if release_dir is not None and effective_dist is not None:
            release_info = package_release_assets(
                src_dir=src_dir,
                out_dir=out_dir,
                dist_dir=effective_dist,
                release_dir=release_dir,
                release_notes_path=release_notes,
                arch=args.arch,
                defconfig=defconfig,
                summary=summary,
            )
    finally:
        if temp_dist_cm is not None:
            temp_dist_cm.cleanup()

    print("\n=== MizKernel Build Complete ===")
    print(f"Duration:       {elapsed:.1f}s")
    print(f"Kernel Release: {summary['kernel_release']}")
    print(f"Images:         {', '.join(summary['images']) or 'none'}")
    print(f"DTBs / DTBOs:   {summary['dtb_count']} / {summary['dtbo_count']}")
    print(f"Modules (.ko):  {summary['module_count']}")
    if dist_dir is not None:
        print(f"Dist dir:       {dist_dir}")
    if release_info is not None:
        print(f"Release dir:    {release_info['release_dir']}")
        print(f"Release assets: {', '.join(release_info['assets'])}")
    return 0


def handle_metadata(args: argparse.Namespace) -> int:
    """Execute the 'metadata' subcommand."""
    src_dir = args.src_dir.resolve()
    defconfig: Optional[str] = None
    try:
        defconfig = resolve_defconfig(src_dir, args.arch, args.defconfig)
    except FileNotFoundError:
        if args.defconfig:
            raise

    metadata, missing_keys = resolve_release_metadata(
        src_dir=src_dir,
        arch=args.arch,
        defconfig=defconfig,
        localversion_override=args.localversion,
        env_keys=args.check_env_key,
        event_name=args.event_name,
        publish_mode=args.publish_release,
        prerelease_mode=args.prerelease,
        release_tag_override=args.release_tag,
        release_name_override=args.release_name,
        strict_env_keys=args.strict_env_keys,
    )

    if args.github_output:
        write_github_output(args.github_output, metadata)
    if args.step_summary:
        summary_md = (
            f"### 📦 Release Metadata: `{metadata['kernel_version']}{metadata['localversion']}` "
            f"(Build `#{metadata['build_number']}`, Tag `{metadata['release_tag']}`, "
            f"Prerelease `{metadata['prerelease']}`, Publish `{metadata['should_release']}`)\n"
        )
        with args.step_summary.open("a", encoding="utf-8") as fh:
            fh.write(summary_md)

    if args.json:
        print(json.dumps(metadata, indent=2))
        return 0

    print("=== MizKernel Release Metadata ===")
    print(f"Repository:     {metadata['repo']}")
    print(f"Event / Ref:    {metadata['event_name']} / {metadata['ref_name']} (tag={metadata['is_tag']})")
    print(f"Defconfig:      {metadata['defconfig'] or '(none)'}")
    print(f"Kernel Version: {metadata['kernel_version']}{metadata['localversion']}")
    print(f"Build Number:   {metadata['build_number']} (Dynamic: {metadata['dynamic_version']})")
    print(f"Commit:         {metadata['short_sha']}")
    for key, present in dict(metadata["env_keys"]).items():
        status = "present" if present else "missing"
        print(f"Env Key {key:<12}: {status}")
    print(f"Release Tag:    {metadata['release_tag']}")
    print(f"Release Name:   {metadata['release_name']}")
    print(f"Prerelease:     {metadata['prerelease']}")
    print(f"Should Release: {metadata['should_release']} ({metadata['release_reason']})")
    if missing_keys and args.event_name != "pull_request" and args.publish_release != "false":
        if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
            print(f"::warning::Missing release env key(s): {', '.join(missing_keys)}")
    return 0


def handle_report(args: argparse.Namespace) -> int:
    """Execute the 'report' subcommand."""
    src_dir = args.src_dir.resolve()
    release_dir = args.release_dir if args.release_dir.is_absolute() else (src_dir / args.release_dir)
    if not release_dir.is_dir():
        raise FileNotFoundError(f"Release directory does not exist: {release_dir}")

    defconfig: Optional[str] = None
    try:
        defconfig = resolve_defconfig(src_dir, args.arch, args.defconfig)
    except FileNotFoundError:
        if args.defconfig:
            raise

    report = generate_release_report(
        src_dir=src_dir,
        release_dir=release_dir,
        arch=args.arch,
        defconfig=defconfig,
        release_tag=args.release_tag,
        prerelease=args.prerelease == "true",
        build_number=args.build_number,
        output_path=args.output,
        step_summary_path=args.step_summary,
    )
    print(report)
    return 0


def handle_checksums(args: argparse.Namespace) -> int:
    """Execute the 'checksums' subcommand."""
    base_dir = Path(__file__).resolve().parent
    release_dir = args.release_dir if args.release_dir.is_absolute() else (base_dir / args.release_dir)
    if not release_dir.is_dir():
        raise FileNotFoundError(f"Release directory does not exist: {release_dir}")
    checksum_lines = write_release_checksums(release_dir)
    print(f"[miz_build] Wrote {len(checksum_lines)} SHA-256 checksum(s) to {release_dir / 'SHA256SUMS.txt'}")
    return 0


def handle_check_ksu(args: argparse.Namespace) -> int:
    """Execute the 'check-ksu' subcommand."""
    src_dir = args.src_dir.resolve()
    defconfig: Optional[str] = None
    try:
        defconfig = resolve_defconfig(src_dir, args.arch, args.defconfig)
    except FileNotFoundError:
        if args.defconfig:
            raise

    info = check_ksu_presence(src_dir, args.arch, defconfig)
    has_hooks_or_kprobes = bool(info["ksu_hook_count"] > 0 or info["kprobes_enabled"])

    if args.github_output:
        lines = [
            f"ksu_present={'true' if info['ksu_present'] else 'false'}",
            f"ksu_status={info['ksu_status']}",
            f"ksu_source_present={'true' if info['ksu_source_present'] else 'false'}",
            f"ksu_source_path={info['ksu_source_path']}",
            f"ksu_kbuild_wired={'true' if info['kbuild_wired'] else 'false'}",
            f"ksu_defconfig_enabled={'true' if info['defconfig_enabled'] else 'false'}",
            f"ksu_hook_count={info['ksu_hook_count']}",
            f"ksu_hooks_or_kprobes={'true' if has_hooks_or_kprobes else 'false'}",
        ]
        with args.github_output.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    if args.step_summary:
        status_icon = "✅" if info["ksu_status"] == "complete" else ("⚠️" if info["ksu_status"] == "partial" else "❌")
        md_lines = [
            f"### {status_icon} KernelSU Presence Check: `{info['ksu_status']}`",
            "",
            "| Component | Status | Details |",
            "| :--- | :--- | :--- |",
            f"| KernelSU Source | {'✅ Present' if info['ksu_source_present'] else '❌ Missing'} | `{info['ksu_source_path'] or 'not found'}` |",
            f"| `drivers/Kconfig` Wiring | {'✅ Present' if info['kconfig_wired'] else '❌ Missing'} | — |",
            f"| `drivers/Makefile` Wiring | {'✅ Present' if info['makefile_wired'] else '❌ Missing'} | — |",
            f"| Defconfig (`CONFIG_KSU`) | {'✅ Enabled' if info['defconfig_enabled'] else '❌ Not enabled'} | `{info['defconfig'] or 'none'}` |",
            f"| Hook Points / Kprobes | {'✅ Detected' if has_hooks_or_kprobes else '⚠️ None detected'} | `{', '.join(info['ksu_hook_files']) or ('CONFIG_KPROBES=y' if info['kprobes_enabled'] else 'none')}` |",
        ]
        with args.step_summary.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(md_lines) + "\n\n")

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print("=== KernelSU Presence Check ===")
        print(f"Status:            {info['ksu_status']} (present={info['ksu_present']})")
        print(f"Defconfig:         {info['defconfig'] or '(none)'}")
        print(f"Source Present:    {info['ksu_source_present']} ({info['ksu_source_path'] or 'none'})")
        print(f"Kconfig Wired:     {info['kconfig_wired']}")
        print(f"Makefile Wired:    {info['makefile_wired']}")
        print(f"Defconfig KSU:     {info['defconfig_enabled']} ({', '.join(info['defconfig_ksu_flags']) or 'none'})")
        print(f"Hooks / Kprobes:   {info['ksu_hook_count']} file(s) ({', '.join(info['ksu_hook_files']) or 'none'}), kprobes={info['kprobes_enabled']}")

    if args.fail_on_missing:
        if not info["ksu_present"]:
            return 1
        if args.require_hooks and not has_hooks_or_kprobes:
            return 1
    return 0


def handle_kconfig(args: argparse.Namespace) -> int:
    """Execute defconfig, menuconfig, nconfig, olddefconfig, or savedefconfig."""
    src_dir, out_dir, subarch, defconfig, toolchains = _resolve_from_args(args)
    need_ncurses = args.command in ("menuconfig", "nconfig")
    results, ctx = run_environment_checks(
        src_dir=src_dir,
        toolchains=toolchains,
        arch=args.arch,
        defconfig=defconfig,
        require_toolchains=True,
        require_ncurses=need_ncurses,
    )
    report, passed = format_env_report(results, ctx, defconfig, toolchains)
    if not passed:
        print(report)
        return 1

    use_lld = args.lld == "on" or (args.lld == "auto" and args.lto in ("thin", "full"))
    make_env = build_make_env(toolchains, args.build_user, args.build_host)
    check_clean_srctree(src_dir, out_dir, args.mrproper_src, make_env)
    out_dir.mkdir(parents=True, exist_ok=True)

    project_name = infer_project_name(src_dir, args.arch, defconfig, args.project_name)
    make_args = build_make_args(
        src_dir=src_dir,
        out_dir=out_dir,
        arch=args.arch,
        subarch=subarch,
        jobs=args.jobs,
        toolchains=toolchains,
        dt_overlay=not args.no_dt_overlay,
        section_mismatch_warn_only=not args.strict_section_mismatch,
        use_lld=use_lld,
        project_name=project_name,
        localversion=args.localversion,
        kcflags=args.kcflags,
        extra_make_args=args.make_arg,
        parallel=not need_ncurses,
    )

    dot_config = out_dir / ".config"
    if args.command == "defconfig":
        if not defconfig:
            raise FileNotFoundError("No defconfig found.")
        run_logged([*make_args, defconfig], make_env)
        return 0

    if not args.no_defconfig and not dot_config.is_file():
        if not defconfig:
            raise FileNotFoundError("No defconfig found to initialize .config.")
        run_logged([*make_args, defconfig], make_env)

    run_logged([*make_args, args.command], make_env)

    if args.command == "savedefconfig":
        generated = out_dir / "defconfig"
        print(f"[miz_build] Generated minimal defconfig: {generated}")
        if getattr(args, "update_defconfig", False):
            if not defconfig:
                raise FileNotFoundError("Cannot update defconfig: target defconfig path is unknown.")
            dest = src_dir / "arch" / args.arch / "configs" / defconfig
            shutil.copy2(generated, dest)
            print(f"[miz_build] Updated defconfig: {dest}")
    return 0


def handle_clean(args: argparse.Namespace) -> int:
    """Execute clean or mrproper."""
    src_dir, out_dir, subarch, _, toolchains = _resolve_from_args(args)
    make_env = build_make_env(toolchains, args.build_user, args.build_host)
    if args.command == "mrproper" and getattr(args, "in_tree", False):
        run_logged(["make", "-C", str(src_dir), f"PYTHON={sys.executable}", "mrproper"], make_env)
        return 0
    if not out_dir.exists():
        print(f"[miz_build] Output directory does not exist: {out_dir}")
        return 0
    run_logged(
        [
            "make",
            "-C",
            str(src_dir),
            f"O={out_dir}",
            f"ARCH={args.arch}",
            f"SUBARCH={subarch}",
            f"PYTHON={sys.executable}",
            args.command,
        ],
        make_env,
    )
    return 0


def _normalize_argv(raw_argv: Sequence[str], known_cmds: set[str]) -> List[str]:
    """Allow common flags before or after the subcommand, defaulting to 'build'."""
    value_opts = {
        "--src-dir", "--out", "--out-dir", "--arch", "--subarch", "--defconfig",
        "--toolchain-dir", "--toolchain", "--clang", "--cross-compile",
        "--clang-triple", "--dtc", "--jobs", "-j", "--project-name",
        "--build-user", "--build-host", "--localversion", "--kcflags",
        "--lld", "--lto", "--distrobox", "--make-arg", "--name",
        "--toolchain-url", "--target", "--dist-dir", "--release-dir",
        "--release-notes", "--check-env-key", "--event-name",
        "--publish-release", "--prerelease", "--release-tag",
        "--release-name", "--github-output", "--step-summary",
        "--build-number", "--output",
    }
    if not raw_argv:
        return ["build"]

    tokens = list(raw_argv)
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in ("-h", "--help"):
            # Let top-level help display if no subcommand was identified yet.
            return tokens if idx == 0 else tokens
        if tok in known_cmds:
            return [tok, *tokens[:idx], *tokens[idx + 1:]]
        if tok.startswith("-"):
            if "=" not in tok and tok in value_opts:
                idx += 2
                continue
            idx += 1
            continue
        # Unknown positional verb -> leave untouched so argparse reports error cleanly.
        return tokens

    return ["build", *tokens]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entrypoint."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    known_cmds = {
        "check",
        "metadata",
        "report",
        "checksums",
        "check-ksu",
        "fetch-toolchains",
        "build",
        "defconfig",
        "menuconfig",
        "nconfig",
        "olddefconfig",
        "savedefconfig",
        "clean",
        "mrproper",
    }
    raw_argv = _normalize_argv(raw_argv, known_cmds)

    parser = build_parser()
    args = parser.parse_args(raw_argv)
    if not args.command:
        parser.print_help()
        return 0

    maybe_reexec_in_distrobox(raw_argv, getattr(args, "distrobox", None))

    try:
        if args.command == "check":
            return handle_check(args)
        if args.command == "metadata":
            return handle_metadata(args)
        if args.command == "report":
            return handle_report(args)
        if args.command == "checksums":
            return handle_checksums(args)
        if args.command == "check-ksu":
            return handle_check_ksu(args)
        if args.command == "fetch-toolchains":
            src_dir = args.src_dir.resolve()
            tc_dir = args.toolchain_dir if args.toolchain_dir.is_absolute() else (src_dir / args.toolchain_dir)
            return fetch_toolchains(
                src_dir,
                tc_dir,
                args.arch,
                args.name,
                args.toolchain_url,
                force=args.force,
                fetch_all=args.fetch_all,
            )
        if args.command == "build":
            return handle_build(args)
        if args.command in ("defconfig", "menuconfig", "nconfig", "olddefconfig", "savedefconfig"):
            return handle_kconfig(args)
        if args.command in ("clean", "mrproper"):
            return handle_clean(args)
    except subprocess.CalledProcessError as exc:
        print(f"[miz_build] Command failed with exit code {exc.returncode}: {shlex.join(exc.cmd)}", file=sys.stderr)
        return exc.returncode or 1
    except Exception as exc:
        print(f"[miz_build] ERROR: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
