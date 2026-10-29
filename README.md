# gimmie

Receive files through a browser using copyparty and a temporary Cloudflare Tunnel URL. The sender only needs a browser.

Status: a personal project. The code is public so that anyone can read it. There is no support, roadmap, or response to issues.

## Start

The receiver needs **Python 3.11 or newer** on Windows, Linux, or macOS. No pip packages, Docker, administrator access, or Cloudflare account are needed. Install Python from [python.org](https://www.python.org/downloads/) if necessary.

- **macOS with the python.org installer:** run `Install Certificates.command` in `/Applications/Python 3.x/` once. Without it, the first downloads fail with `CERTIFICATE_VERIFY_FAILED`.
- **Linux:** python.org offers only source code. If `python3 --version` is older than 3.11, install a newer Python with your package manager and run it by name, for example `python3.11 start.py`.

Windows PowerShell:

```powershell
py -3 start.py
```

Linux or macOS:

```sh
python3 start.py
```

copyparty runs from `copyparty-sfx.py` beside `start.py`. The same self-contained Python file works across Windows, Linux, and macOS. If it is missing, the launcher downloads the official [copyparty v1.20.26 release](https://github.com/9001/copyparty/releases/tag/v1.20.26) and verifies its SHA-256 checksum. An existing file is reused without network or version checks; there are no automatic upgrades.

cloudflared is specific to the operating system and CPU. If needed, the launcher downloads the official [cloudflared 2026.10.5 release](https://github.com/cloudflare/cloudflared/releases/tag/2026.10.5) into `.gimmie/bin/`, verifies its SHA-256 checksum, and reuses it on later runs. A `cloudflared.exe` on Windows, or `cloudflared` on Linux/macOS, beside the launcher is used instead when present.

The launcher asks no questions. It reads `gimmie.toml`, generates a new random 17-character password for each account without a configured one, and starts.

## Share and stop

After both services start, the launcher prints a block like this for the default password-only login:

```text
URL:      https://<random-words>.trycloudflare.com/incoming
Password: <generated or configured password>
```

When `require_username` is `true`, the block also includes `Username`, and the sender enters both their username and password in the browser.

The URL and uploader login details are copied together to your clipboard when supported. Windows and macOS use their native clipboard; Linux uses an available `wl-copy`, `xclip`, or `xsel`. No clipboard tools are installed automatically. If copying is unavailable, copy the printed block manually, or use `--no-clipboard` to skip copying.

Admin credentials are printed separately and are never included in the clipboard block. If you configure multiple uploaders, the share block contains every uploader's login details. Password-only mode adds `Account: <name>` labels to distinguish them; senders still enter only their password in that mode.

Keep the terminal open while receiving files. **Ctrl+C** stops copyparty and the tunnel; on Linux and macOS, so does closing the terminal. The tunnel URL changes each run and stops working when the tunnel stops. Cloudflare Quick Tunnels have no uptime guarantee; see the [Quick Tunnel documentation](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

## Configuration

Settings live in `gimmie.toml`. A comment beside each field lists its allowed values. The defaults are an `owner` admin account and a `guest` upload account, with a new password for each on every run. To keep the same password across runs, add a `password` line to that account. Use `--config /path/to/other.toml` for another settings file.

`copyparty.conf` is a template for the launcher, including the free-space limit and the tunnel settings. It also hides the machine's hostname and turns off copyparty's share links. It serves uploaded HTML as plain text and never shows an uploaded folder banner or README, so an uploader cannot run a script in the admin's browser. The launcher fills in the port, receiving path, accounts, and permissions at startup. Do not launch copyparty against the template directly. The temporary file containing credentials is removed when the launcher shuts down normally or through Ctrl+C.

## Files and troubleshooting

- Uploads go into `incoming/` by default and support resumable transfers. There is no limit on file size or total size; uploads stop when less than 5 GiB of disk space is free (`df` in `copyparty.conf`).
- Logs and service state stay under `.gimmie/`; log paths are printed at startup. copyparty keeps its upload-resume data, which includes uploaders' IP addresses, in `.hist/` inside the receiving folder. copyparty listens only on `127.0.0.1`. The tunnel connects outbound using HTTP/2.
- Use `--startup-timeout 120` if startup needs more than the default 60 seconds.
- Before distributing the folder, run `python3 start.py --prepare` (or `py -3 start.py --prepare`) to download missing tools without starting a tunnel. Include the resulting `copyparty-sfx.py` with `start.py` and the configuration files; it carries its own license notices (`python3 copyparty-sfx.py --license`). This bundles the portable copyparty file for every supported OS. To also avoid cloudflared downloads on a matching OS/CPU, include its prepared `.gimmie/bin/` cache. Internet access is still required to create and use the tunnel.
- To update copyparty, manually replace `copyparty-sfx.py` with a newer file from the [official releases](https://github.com/9001/copyparty/releases).
- To update cloudflared, set `CLOUDFLARED_VERSION` and the `CLOUDFLARED_SHA256` values in `start.py` from the `sha256:` digest next to each asset on the release page (not the list in the release notes, which differs for the macOS files). Then delete `.gimmie/bin/`; a `cloudflared` beside `start.py` is used instead of any download.
- Run `python3 start.py --help` for all options.
