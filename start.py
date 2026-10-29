#!/usr/bin/env python3
"""Portable copyparty + Cloudflare Tunnel launcher; Python standard library only."""

import sys

if sys.version_info < (3, 11):
    sys.exit("Python 3.11 or newer is required. Download it from https://www.python.org/downloads/.")

import argparse
import contextlib
import hashlib
import http.client
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tarfile
import tempfile
import time
import tomllib
import unicodedata
import urllib.request
from dataclasses import dataclass, field


ROOT = Path(__file__).resolve().parent
COPYPARTY_VERSION = "1.20.26"
COPYPARTY_URL = f"https://github.com/9001/copyparty/releases/download/v{COPYPARTY_VERSION}/copyparty-sfx.py"
COPYPARTY_SHA256 = "8f9a0def8a9c15252a06395781ec083372043b60caa80fb33c3d6dafa7f1b40a"
CLOUDFLARED_VERSION = "2026.10.5"
CLOUDFLARED_URL = f"https://github.com/cloudflare/cloudflared/releases/download/{CLOUDFLARED_VERSION}/"
# GitHub's own asset digests: the release notes list different hashes for the macOS .tgz files.
CLOUDFLARED_SHA256 = {
    "cloudflared-darwin-amd64.tgz": "6699392fed92367808c248c2d90bed66e49bbf66e1b4ee3e4141230f3f7391b3",
    "cloudflared-darwin-arm64.tgz": "184c7d4f5f977348243a6d7ca8f6cf6073b9b2746cfe8c1fe15aa59e9a522bf0",
    "cloudflared-linux-386": "f2de713829081837130b38e27f3c95aa9d7fc1a4f48b833362d21234dd8780d8",
    "cloudflared-linux-amd64": "e1bc0cf084fd9e590554fe769a86b1db46701c3f847a43d902f7b974a4e16298",
    "cloudflared-linux-arm": "a018911e1bbfd739937f3011f589e9e73245baeee14742f8b3413472bb007adc",
    "cloudflared-linux-arm64": "72e0d05a67e09da87cf495e409a28c3cc5994dd23fc66a982eebea6a55923b7d",
    "cloudflared-linux-armhf": "4aed2f4179f2ac1068b45073761409ba4540a631a2e70df98543a65b4a982d27",
    "cloudflared-windows-386.exe": "66cba8003e4f87a8e6b772f331b8c04c7d41ac4f2dc30dd2c13ae09de3b6007e",
    "cloudflared-windows-amd64.exe": "db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9",
}
USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
TUNNEL_URL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com\b", re.I)


@dataclass
class User:
    role: str
    username: str
    password: str = field(repr=False)


def validate_username(value: str) -> None:
    if not USERNAME.fullmatch(value) or value.casefold() == "leeloo_dallas":
        raise ValueError("Username must be 1-64 letters, digits, dots, underscores or hyphens; leeloo_dallas is reserved.")


def validate_config_text(value: str, label: str) -> None:
    # copyparty strips edge whitespace and treats two spaces followed by # as a comment.
    if value != value.strip() or "  #" in value or any(unicodedata.category(c) in ("Cc", "Zl", "Zp") for c in value):
        raise ValueError(f"{label} cannot contain control characters, edge whitespace, or two spaces followed by #.")


def load_config(path: Path) -> dict:
    path = Path(path).resolve()
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read config {path}: {exc}") from exc
    unknown = set(config) - {"port", "incoming_dir", "require_username", "users"}
    if unknown:
        raise ValueError(f"Unknown config option(s): {', '.join(sorted(unknown))}")
    port = config.get("port", 3923)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535.")
    incoming = config.get("incoming_dir", "incoming")
    if not isinstance(incoming, str) or not incoming:
        raise ValueError("incoming_dir must be a nonempty path.")
    validate_config_text(incoming, "incoming_dir")
    incoming = (path.parent / Path(incoming).expanduser()).resolve()
    validate_config_text(str(incoming), "Resolved incoming_dir")
    require_username = config.get("require_username", False)
    if type(require_username) is not bool:
        raise ValueError("require_username must be true or false.")
    users = config.get("users")
    if not isinstance(users, list) or not users:
        raise ValueError("Configure at least one [[users]] account.")
    names = set()
    roles = set()
    passwords = []
    for entry in users:
        if not isinstance(entry, dict) or set(entry) - {"role", "username", "password"}:
            raise ValueError("Each user may contain only role, username and password.")
        role = entry.get("role")
        if role not in ("admin", "upload"):
            raise ValueError('Every user needs role "admin" or "upload".')
        roles.add(role)
        for key in ("username", "password"):
            if not isinstance(entry.get(key, ""), str):
                raise ValueError(f"User {key} must be a string.")
        name = entry.get("username", "")
        validate_username(name)
        if name.casefold() in names:
            raise ValueError("Usernames must be unique (ignoring case).")
        names.add(name.casefold())
        password = entry.get("password", "")
        validate_config_text(password, "Password")
        if password:
            passwords.append(password)
    if roles != {"admin", "upload"}:
        raise ValueError("Configure at least one admin and one upload user.")
    # Password-only login identifies the account by its password.
    if not require_username and len(set(passwords)) != len(passwords):
        raise ValueError("Each account needs a different password for password-only login.")
    return {"port": port, "incoming_dir": incoming, "require_username": require_username, "users": users}


def collect_users(config: dict) -> list[User]:
    taken = {entry.get("password", "") for entry in config["users"]} - {""}
    users = []
    for entry in config["users"]:
        password = entry.get("password", "")
        while not password:
            # 17 URL-safe characters retain 102 bits of cryptographic randomness.
            candidate = secrets.token_urlsafe(13)[:17]
            if candidate not in taken:
                password = candidate
        taken.add(password)
        users.append(User(entry["role"], entry["username"], password))
    return users


def render_config(template: str, config: dict, users: list[User]) -> str:
    replacements = {
        "__GIMMIE_PORT__": str(config["port"]),
        "__GIMMIE_INCOMING_DIR__": str(config["incoming_dir"]),
        "__GIMMIE_ADMIN_USERS__": ", ".join(user.username for user in users if user.role == "admin"),
        "__GIMMIE_UPLOAD_USERS__": ", ".join(user.username for user in users if user.role == "upload"),
        "__GIMMIE_LOGIN_OPTIONS__": "usernames" if config.get("require_username", False) else "# password-only login",
    }
    for token, value in replacements.items():
        if token not in template:
            raise ValueError(f"copyparty.conf is missing template marker {token}.")
        template = template.replace(token, value)
    if "__GIMMIE_" in template:
        raise ValueError("Unknown template marker in copyparty.conf.")
    accounts = "\n".join(f"  {user.username}: {user.password}" for user in users)
    return f"[accounts]\n{accounts}\n\n{template}"


def cloudflared_asset(system: str, machine: str) -> str:
    machine = machine.lower()
    arches = {"amd64": "amd64", "x86_64": "amd64", "x64": "amd64",
              "i386": "386", "i686": "386", "x86": "386", "aarch64": "arm64",
              "arm64": "arm64", "armv6l": "arm", "armv7l": "armhf", "armv8l": "armhf"}
    arch = arches.get(machine)
    if system == "Windows" and arch in ("amd64", "386", "arm64"):
        # Cloudflare ships no Windows ARM binary; Windows 11 ARM supports x64 emulation.
        return f"cloudflared-windows-{'amd64' if arch == 'arm64' else arch}.exe"
    if system == "Darwin" and arch in ("amd64", "arm64"):
        return f"cloudflared-darwin-{arch}.tgz"
    if system == "Linux" and arch:
        return f"cloudflared-linux-{arch}"
    raise ValueError(f"No automatic cloudflared download for {system}/{machine}. Place a compatible cloudflared executable beside start.py.")


def download(url: str, destination: Path, expected_sha256: str | None = None) -> None:
    print(f"Downloading {url.rsplit('/', 1)[-1]} ...", flush=True)
    temporary = None
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "gimmie-launcher"})
        with urllib.request.urlopen(request, timeout=60) as response:
            with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
                temporary = Path(output.name)
                shutil.copyfileobj(response, output)
            size = temporary.stat().st_size
            expected = response.headers.get("Content-Length")
            if not size or (expected and size != int(expected)):
                raise OSError("Incomplete download.")
            if expected_sha256 and hashlib.sha256(temporary.read_bytes()).hexdigest() != expected_sha256:
                raise OSError("Downloaded file does not match its expected SHA-256 checksum.")
        temporary.replace(destination)
    except OSError as exc:
        raise OSError(f"Download failed: {url}\n{exc}\nDownload it manually and place it at {destination}.") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def extract_cloudflared(archive: Path, destination: Path) -> None:
    # Copy only the expected regular file; never extract archive paths or links.
    with tarfile.open(archive, "r:gz") as bundle:
        members = [m for m in bundle.getmembers() if m.name in ("cloudflared", "./cloudflared") and m.isfile()]
        if len(members) != 1:
            raise ValueError("cloudflared archive must contain one regular cloudflared file.")
        source = bundle.extractfile(members[0])
        if source is None:
            raise ValueError("cloudflared archive member cannot be read.")
        with contextlib.closing(source):
            with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
                temporary = Path(output.name)
                try:
                    shutil.copyfileobj(source, output)
                except BaseException:
                    output.close()
                    temporary.unlink(missing_ok=True)
                    raise
        try:
            if temporary.stat().st_size == 0:
                raise ValueError("cloudflared archive contains an empty executable.")
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)


def ensure_tools(root: Path = ROOT) -> tuple[list[str], list[str]]:
    system, machine = platform.system(), platform.machine()
    cache = root / ".gimmie" / "bin" / f"{system}-{machine.lower()}"
    cache.mkdir(parents=True, exist_ok=True)
    party = root / "copyparty-sfx.py"
    if not party.is_file():
        # One portable file travels with the folder and works on every platform.
        download(COPYPARTY_URL, party, expected_sha256=COPYPARTY_SHA256)
    tunnel = root / ("cloudflared.exe" if system == "Windows" else "cloudflared")
    if not tunnel.is_file():
        tunnel = cache / tunnel.name
        if not tunnel.is_file():
            asset = cloudflared_asset(system, machine)
            if asset.endswith(".tgz"):
                with tempfile.TemporaryDirectory(prefix="gimmie-download-") as directory:
                    archive = Path(directory) / asset
                    download(CLOUDFLARED_URL + asset, archive, expected_sha256=CLOUDFLARED_SHA256[asset])
                    extract_cloudflared(archive, tunnel)
            else:
                download(CLOUDFLARED_URL + asset, tunnel, expected_sha256=CLOUDFLARED_SHA256[asset])
    # A cloudflared beside start.py may be a symlink to a system binary the user cannot chmod.
    if system != "Windows" and not os.access(tunnel, os.X_OK):
        tunnel.chmod(tunnel.stat().st_mode | 0o100)
    return [sys.executable, str(party)], [str(tunnel)]


def check_port(port: int) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise OSError(f"Cannot use 127.0.0.1:{port}; it may already be in use. Stop the other receiver or change port in gimmie.toml.") from exc


def require_running(process, label: str, log: Path) -> None:
    code = process.poll()
    if code is not None:
        raise RuntimeError(f"{label} exited with code {code}. See {log}")


def wait_for_server(process, port: int, timeout: float, log: Path) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require_running(process, "copyparty", log)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=min(1, timeout))
        try:
            connection.request("GET", "/incoming/")
            response = connection.getresponse()
            if 200 <= response.status < 500:
                require_running(process, "copyparty", log)
                return
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(0.2)
    raise RuntimeError(f"copyparty was not ready after {timeout:g}s. See {log}")


def wait_for_tunnel(party, tunnel, log: Path, party_log: Path, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    seen = ""
    url = None
    connected = False
    with log.open(encoding="utf-8", errors="replace") as stream:
        while time.monotonic() < deadline:
            require_running(party, "copyparty", party_log)
            require_running(tunnel, "cloudflared", log)
            seen += stream.read()
            match = TUNNEL_URL.search(seen)
            if match:
                url = match.group(0)
            connected = connected or "registered tunnel connection" in seen.lower()
            if url and connected:
                return url
            # Keep partial lines and avoid repeatedly rescanning an unbounded log.
            seen = seen[-16384:]
            time.sleep(0.2)
    raise RuntimeError(f"No connected tunnel after {timeout:g}s. See {log}")


def format_share(url: str, users: list[User], require_username: bool = False) -> str:
    blocks = []
    uploaders = [user for user in users if user.role == "upload"]
    for user in uploaders:
        label = f"Account:  {user.username}\n" if len(uploaders) > 1 and not require_username else ""
        username = f"Username: {user.username}\n" if require_username else ""
        blocks.append(f"{label}URL:      {url.rstrip('/')}/incoming/\n{username}Password: {user.password}")
    return "\n\n".join(blocks)


def copy_to_clipboard(text: str) -> bool:
    system = platform.system()
    commands = []
    payload = text.encode("utf-8")
    if system == "Windows":
        # clip.exe expects UTF-16LE for Unicode text.
        commands = [["clip.exe"]]
        payload = text.encode("utf-16le")
    elif system == "Darwin":
        commands = [["pbcopy"]]
    else:
        if os.environ.get("WAYLAND_DISPLAY"):
            commands.append(["wl-copy"])
        if os.environ.get("DISPLAY"):
            commands.extend([["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]])
    for command in commands:
        if not shutil.which(command[0]):
            continue
        try:
            result = subprocess.run(command, input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            if result.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
    return False


def start_process(command: list[str], log, environment: dict, cwd: Path):
    return subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=os.name != "nt", creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))


def stop_process(process) -> None:
    if process is None:
        return
    if os.name == "nt":
        if process.poll() is not None:
            return
        # /T includes child processes; no shell or interpolated command strings.
        try:
            result = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if result.returncode != 0 and process.poll() is None:
                process.kill()
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()
        process.wait()
        return
    # Kill the session's process group even if its parent already exited.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def run(config: dict, users: list[User], tools: tuple[list[str], list[str]], timeout: float, clipboard: bool) -> None:
    check_port(config["port"])
    config["incoming_dir"].mkdir(parents=True, exist_ok=True)
    state = ROOT / ".gimmie"
    logs = state / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    config_home = state / "state"
    config_home.mkdir(exist_ok=True)
    session = f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
    party_log, tunnel_log = logs / f"copyparty-{session}.log", logs / f"cloudflared-{session}.log"
    rendered = render_config((ROOT / "copyparty.conf").read_text(encoding="utf-8-sig"), config, users)
    environment = os.environ.copy()
    environment.update({"XDG_CONFIG_HOME": str(config_home), "PYTHONUNBUFFERED": "1", "NO_COLOR": "1"})
    # Ignore unrelated auto-loaded copyparty config files inherited from the caller.
    environment.pop("PRTY_CONFIG", None)
    party = tunnel = None
    print(f"copyparty log: {party_log}\nTunnel log:   {tunnel_log}", flush=True)
    with tempfile.TemporaryDirectory(prefix="gimmie-session-") as directory:
        runtime = Path(directory)
        runtime_config = runtime / "copyparty.conf"
        with runtime_config.open("x", encoding="utf-8", newline="\n") as output:
            if os.name != "nt":
                os.fchmod(output.fileno(), 0o600)
            output.write(rendered)
        # Explicit empty config prevents the operator's existing cloudflared config
        # from disabling Quick Tunnels or changing this launch's settings.
        tunnel_config = runtime / "cloudflared.yml"
        tunnel_config.write_text("{}\n", encoding="utf-8")
        with party_log.open("wb") as party_output, tunnel_log.open("wb") as tunnel_output:
            try:
                party = start_process(tools[0] + ["-c", str(runtime_config), "--no-ansi"],
                                      party_output, environment, ROOT)
                print("Waiting for copyparty ...", flush=True)
                wait_for_server(party, config["port"], timeout, party_log)
                tunnel = start_process(tools[1] + ["tunnel", "--config", str(tunnel_config), "--no-autoupdate", "--protocol", "http2",
                                       "--url", f"http://127.0.0.1:{config['port']}"], tunnel_output, environment, ROOT)
                print("Waiting for the tunnel ...", flush=True)
                url = wait_for_tunnel(party, tunnel, tunnel_log, party_log, timeout)
                share = format_share(url, users, config.get("require_username", False))
                print(f"\nSend to uploader(s):\n\n{share}\n", flush=True)
                if clipboard:
                    print("Upload URL and credentials copied to clipboard." if copy_to_clipboard(share)
                          else "Clipboard unavailable; copy the upload details above.", flush=True)
                print("\nAdmin credentials (keep these):", flush=True)
                for user in users:
                    if user.role == "admin":
                        print(f"URL:      {url}/incoming/\nUsername: {user.username}\nPassword: {user.password}\n", flush=True)
                print(f"Uploads: {config['incoming_dir']}\nCtrl+C to stop both processes.\n", flush=True)
                while True:
                    require_running(party, "copyparty", party_log)
                    require_running(tunnel, "cloudflared", tunnel_log)
                    time.sleep(0.5)
            finally:
                # A second Ctrl+C should not interrupt cleanup halfway through.
                previous = {s: signal.signal(s, signal.SIG_IGN) for s in (signal.SIGINT, *STOP_SIGNALS)}
                try:
                    try:
                        stop_process(tunnel)
                    finally:
                        stop_process(party)
                finally:
                    for s, handler in previous.items():
                        signal.signal(s, handler)


def positive_seconds(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return number


def request_stop(signum, frame) -> None:
    raise KeyboardInterrupt


# Closing the terminal sends SIGHUP; the children run in their own session, so without this they outlive it.
STOP_SIGNALS = tuple(s for s in (signal.SIGTERM, getattr(signal, "SIGHUP", None)) if s is not None)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "gimmie.toml", help="TOML settings file (default: beside start.py)")
    parser.add_argument("--no-clipboard", action="store_true", help="print connection details without copying them")
    parser.add_argument("--prepare", action="store_true", help="download missing tools, then exit without starting a tunnel")
    parser.add_argument("--startup-timeout", type=positive_seconds, default=60, metavar="SECONDS", help="timeout for each startup stage (default: 60)")
    args = parser.parse_args(argv)
    # An inherited ignore stays (nohup python3 start.py &); otherwise a hangup or SIGTERM becomes a clean stop.
    previous = {s: signal.signal(s, request_stop) for s in STOP_SIGNALS if signal.getsignal(s) is not signal.SIG_IGN}
    try:
        if args.prepare:
            tools = ensure_tools()
            print(f"Tools ready:\n  copyparty: {tools[0][-1]}\n  cloudflared: {tools[1][0]}")
            return 0
        config = load_config(args.config)
        check_port(config["port"])
        users = collect_users(config)
        tools = ensure_tools()
        run(config, users, tools, args.startup_timeout, not args.no_clipboard)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
    return 0


if __name__ == "__main__":
    sys.exit(main())
