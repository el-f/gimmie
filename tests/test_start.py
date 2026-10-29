"""Regression tests for the portable launcher; no downloads or public tunnels."""

import contextlib
import hashlib
import http.server
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import start  # noqa: E402


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gimmie-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config_path = self.root / "settings.toml"
        self.settings = {
            "port": 3923,
            "incoming_dir": "received files",
            "users": [
                {"role": "admin", "username": "operator", "password": "admin-secret"},
                {"role": "upload", "username": "visitor", "password": "upload-secret"},
            ],
        }

    def config(self, settings=None):
        settings = self.settings if settings is None else settings
        # JSON scalars, strings, arrays and empty tables are valid TOML values.
        lines = [f"{key} = {json.dumps(value)}" for key, value in settings.items() if key != "users"]
        for user in settings.get("users", []):
            lines += ["[[users]]"] + [f"{key} = {json.dumps(value)}" for key, value in user.items()]
        self.config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return start.load_config(self.config_path)

    def test_config_resolves_upload_path_relative_to_config(self):
        config = self.config()
        self.assertEqual(config["incoming_dir"], self.root / "received files")
        self.assertEqual(config["users"][0]["username"], "operator")
        self.assertIs(config["require_username"], False)

    def test_username_login_is_an_explicit_boolean_option(self):
        self.settings["require_username"] = True
        self.assertIs(self.config()["require_username"], True)
        for value in (0, 1, "true", "false", [], {}):
            with self.subTest(value=value):
                self.settings["require_username"] = value
                with self.assertRaisesRegex(ValueError, "require_username"):
                    self.config()

    def test_multiple_configured_users_are_supported(self):
        self.settings["users"].append({"role": "upload", "username": "second_friend", "password": "different-secret"})
        users = start.collect_users(self.config())
        self.assertEqual([user.username for user in users], ["operator", "visitor", "second_friend"])

    def test_invalid_ports_are_rejected(self):
        for port in (True, 0, -1, 65536, "3923", 3923.0):
            with self.subTest(port=port):
                self.settings["port"] = port
                with self.assertRaisesRegex(ValueError, "port"):
                    self.config()

    def test_usernames_reject_wildcard_reserved_and_ambiguous_names(self):
        for name in ("*", "LEElOO_DALLAS", "name,other", "name:password", "with space", "a" * 65, "line\nadmin"):
            with self.subTest(name=name):
                self.settings["users"][1]["username"] = name
                with self.assertRaisesRegex(ValueError, "Username"):
                    self.config()
        self.settings["users"][1]["username"] = "OPERATOR"
        with self.assertRaisesRegex(ValueError, "unique"):
            self.config()
        del self.settings["users"][1]["username"]
        with self.assertRaisesRegex(ValueError, "Username"):
            self.config()

    def test_invalid_roles_and_unknown_options_are_rejected(self):
        self.settings["users"][1]["role"] = "readwrite"
        with self.assertRaisesRegex(ValueError, "role"):
            self.config()
        self.settings["users"][1]["role"] = "admin"
        with self.assertRaisesRegex(ValueError, "at least one"):
            self.config()
        self.settings["users"][1]["role"] = "upload"
        self.settings["password_mode"] = "generate"
        with self.assertRaisesRegex(ValueError, "Unknown config"):
            self.config()

    def test_config_password_and_path_cannot_inject_config_lines(self):
        for bad in (" leading", "trailing ", "one  #comment", "a\tb", "a\nb", "a\rb", "a\x00b", "a\u0085b", "a\u2028b", "a\u2029b"):
            with self.subTest(bad=repr(bad)):
                self.settings["users"][1]["password"] = bad
                with self.assertRaisesRegex(ValueError, "Password"):
                    self.config()
        self.settings["users"][1]["password"] = "safe"
        self.settings["incoming_dir"] = "uploads\n[accounts]"
        with self.assertRaisesRegex(ValueError, "incoming_dir"):
            self.config()

    def test_spaces_quotes_colons_and_single_hash_survive_password_rendering(self):
        password = "a long 'quoted' \"password\":with#hash\\slash"
        self.settings["users"][1]["password"] = password
        config = self.config()
        users = start.collect_users(config)
        template = (ROOT / "copyparty.conf").read_text(encoding="utf-8-sig")
        rendered = start.render_config(template, config, users)
        self.assertIn("  visitor: " + password + "\n", rendered)
        self.assertIn("rw: operator", rendered)
        self.assertIn("w: visitor", rendered)
        self.assertIn(str(self.root / "received files"), rendered)
        self.assertNotIn("__GIMMIE_", rendered)
        self.assertNotIn("\n  usernames\n", rendered)
        self.assertNotIn("admin-secret", repr(users[0]))

    def test_rendered_config_hides_the_hostname_and_disables_uploader_content(self):
        config = self.config()
        rendered = start.render_config((ROOT / "copyparty.conf").read_text(encoding="utf-8-sig"), config, start.collect_users(config))
        lines = {line.strip() for line in rendered.splitlines()}
        self.assertTrue({"name: gimmie", "no-html", "no-logues", "no-readme"} <= lines)
        self.assertFalse(any(line.startswith(("shr:", "shr-adm:")) for line in lines), "an uploader must not be able to create shares")

    def test_incoming_dir_expands_home(self):
        with mock.patch.dict(start.os.environ, {"HOME": str(self.root), "USERPROFILE": str(self.root)}):
            self.settings["incoming_dir"] = "~/inbox"
            self.assertEqual(self.config()["incoming_dir"], (self.root / "inbox").resolve())

    def test_rendered_login_mode_matches_configuration(self):
        template = (ROOT / "copyparty.conf").read_text(encoding="utf-8-sig")
        for require_username in (False, True):
            with self.subTest(require_username=require_username):
                self.settings["require_username"] = require_username
                config = self.config()
                rendered = start.render_config(template, config, start.collect_users(config))
                self.assertEqual("\n  usernames\n" in rendered, require_username)
                self.assertNotIn("__GIMMIE_", rendered)

    def test_missing_or_empty_password_generates_a_unique_strong_password(self):
        del self.settings["users"][0]["password"]
        self.settings["users"][1]["password"] = ""
        first, second = start.collect_users(self.config()), start.collect_users(self.config())
        self.assertTrue(all(len(user.password) == 17 for user in first + second))
        self.assertNotEqual(first[0].password, first[1].password)
        self.assertNotEqual(first[0].password, second[0].password)

    def test_configured_password_is_kept_and_missing_one_generated(self):
        del self.settings["users"][1]["password"]
        users = start.collect_users(self.config())
        self.assertEqual(users[0].password, "admin-secret")
        self.assertEqual(len(users[1].password), 17)

    def test_duplicate_configured_passwords_are_rejected_for_password_only_login(self):
        self.settings["users"][1]["password"] = "admin-secret"
        with self.assertRaisesRegex(ValueError, "different password"):
            self.config()

    def test_username_login_allows_duplicate_configured_passwords(self):
        self.settings["require_username"] = True
        self.settings["users"][1]["password"] = "admin-secret"
        users = start.collect_users(self.config())
        self.assertEqual([user.username for user in users], ["operator", "visitor"])
        self.assertEqual([user.password for user in users], ["admin-secret", "admin-secret"])

    def test_generated_password_retries_collision_with_later_configured_password(self):
        self.settings["users"][0]["password"] = "x" * 17
        self.settings["users"][1]["password"] = ""
        self.settings["users"].reverse()
        for require_username in (False, True):
            with self.subTest(require_username=require_username):
                self.settings["require_username"] = require_username
                with mock.patch.object(start.secrets, "token_urlsafe", side_effect=["x" * 18, "y" * 18]) as generate:
                    users = start.collect_users(self.config())
                self.assertEqual(generate.call_count, 2)
                self.assertEqual([user.password for user in users], ["y" * 17, "x" * 17])

    def test_generated_password_retries_collision_with_another_generated_password(self):
        for entry in self.settings["users"]:
            del entry["password"]
        for require_username in (False, True):
            with self.subTest(require_username=require_username):
                self.settings["require_username"] = require_username
                with mock.patch.object(start.secrets, "token_urlsafe", side_effect=["a" * 18, "a" * 18, "b" * 18]) as generate:
                    users = start.collect_users(self.config())
                self.assertEqual(generate.call_count, 3)
                self.assertEqual([user.password for user in users], ["a" * 17, "b" * 17])

    def test_share_contains_upload_credentials_only(self):
        users = start.collect_users(self.config())
        share = start.format_share("https://example.trycloudflare.com/", users)
        self.assertIn("https://example.trycloudflare.com/incoming/", share)
        self.assertIn("upload-secret", share)
        self.assertNotIn("Username:", share)
        self.assertNotIn("Account:", share)
        self.assertNotIn("visitor", share)
        self.assertNotIn("operator", share)
        self.assertNotIn("admin-secret", share)

    def test_multiple_uploaders_share_labeled_password_blocks(self):
        self.settings["users"].append({"role": "upload", "username": "second_friend", "password": "different-secret"})
        share = start.format_share("https://example.trycloudflare.com", start.collect_users(self.config()))
        self.assertRegex(share, r"Account:\s+visitor\n")
        self.assertRegex(share, r"Account:\s+second_friend\n")
        self.assertIn("upload-secret", share)
        self.assertIn("different-secret", share)
        self.assertNotIn("Username:", share)
        self.assertNotIn("operator", share)
        self.assertNotIn("admin-secret", share)

    def test_username_login_share_includes_uploader_username_and_password(self):
        users = start.collect_users(self.config())
        share = start.format_share("https://example.trycloudflare.com", users, require_username=True)
        self.assertIn("https://example.trycloudflare.com/incoming/", share)
        self.assertRegex(share, r"Username:\s+visitor\n")
        self.assertIn("upload-secret", share)
        self.assertNotIn("operator", share)
        self.assertNotIn("admin-secret", share)

    def test_multiple_uploaders_in_username_mode_have_username_lines_without_account_labels(self):
        self.settings["users"].append({"role": "upload", "username": "second_friend", "password": "different-secret"})
        share = start.format_share("https://example.trycloudflare.com", start.collect_users(self.config()), require_username=True)
        self.assertRegex(share, r"Username:\s+visitor\n")
        self.assertRegex(share, r"Username:\s+second_friend\n")
        self.assertNotIn("Account:", share)
        self.assertNotIn("operator", share)
        self.assertNotIn("admin-secret", share)

    def test_platform_release_selection(self):
        platforms = [
            ("Linux", "x86_64", "cloudflared-linux-amd64"),
            ("Linux", "aarch64", "cloudflared-linux-arm64"),
            ("Linux", "armv7l", "cloudflared-linux-armhf"),
            ("Linux", "i686", "cloudflared-linux-386"),
            ("Darwin", "arm64", "cloudflared-darwin-arm64.tgz"),
            ("Darwin", "x86_64", "cloudflared-darwin-amd64.tgz"),
            ("Windows", "AMD64", "cloudflared-windows-amd64.exe"),
        ]
        for system, machine, expected in platforms:
            with self.subTest(system=system, machine=machine):
                self.assertEqual(start.cloudflared_asset(system, machine), expected)
        with self.assertRaisesRegex(ValueError, "compatible cloudflared"):
            start.cloudflared_asset("Linux", "mystery-cpu")

    def test_every_downloadable_cloudflared_asset_is_pinned_and_verified(self):
        machines = {"Linux": ["x86_64", "i686", "aarch64", "armv6l", "armv7l", "armv8l"], "Darwin": ["x86_64", "arm64"], "Windows": ["AMD64", "x86", "ARM64"]}
        assets = {start.cloudflared_asset(system, machine) for system, names in machines.items() for machine in names}
        self.assertEqual(assets, set(start.CLOUDFLARED_SHA256))
        self.assertIn(f"/releases/download/{start.CLOUDFLARED_VERSION}/", start.CLOUDFLARED_URL)
        (self.root / "copyparty-sfx.py").write_text("# local copyparty", encoding="utf-8")

        def downloaded(url, destination, expected_sha256=None):
            destination.write_bytes(b"cloudflared")

        with mock.patch.object(start.platform, "system", return_value="Windows"), mock.patch.object(start.platform, "machine", return_value="AMD64"), mock.patch.object(start, "download", side_effect=downloaded) as download:
            start.ensure_tools(self.root)
        self.assertEqual(download.call_args.kwargs["expected_sha256"], start.CLOUDFLARED_SHA256["cloudflared-windows-amd64.exe"])

        archive = self.make_archive([("cloudflared", b"mac cloudflared", None)]).read_bytes()

        def downloaded_archive(url, destination, expected_sha256=None):
            destination.write_bytes(archive)

        with mock.patch.object(start.platform, "system", return_value="Darwin"), mock.patch.object(start.platform, "machine", return_value="arm64"), mock.patch.object(start, "download", side_effect=downloaded_archive) as download:
            start.ensure_tools(self.root)
        self.assertEqual(download.call_args.kwargs["expected_sha256"], start.CLOUDFLARED_SHA256["cloudflared-darwin-arm64.tgz"])

    def make_archive(self, entries):
        archive = self.root / "cloudflared.tgz"
        with tarfile.open(archive, "w:gz") as bundle:
            for name, body, link in entries:
                member = tarfile.TarInfo(name)
                if link is not None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = link
                    bundle.addfile(member)
                else:
                    member.size = len(body)
                    bundle.addfile(member, io.BytesIO(body))
        return archive

    def test_archive_extracts_only_regular_executable_never_untrusted_paths(self):
        archive = self.make_archive([
            ("../../outside", b"escape", None),
            ("./cloudflared", b"native executable", None),
            ("extra-link", b"", "../../outside"),
        ])
        destination = self.root / "native"
        start.extract_cloudflared(archive, destination)
        self.assertEqual(destination.read_bytes(), b"native executable")
        self.assertEqual({path.name for path in self.root.iterdir()}, {"cloudflared.tgz", "native"})

    def test_archive_symlink_and_duplicate_executables_are_rejected(self):
        destination = self.root / "native"
        archive = self.make_archive([("cloudflared", b"", "../../outside")])
        with self.assertRaisesRegex(ValueError, "one regular"):
            start.extract_cloudflared(archive, destination)
        archive = self.make_archive([("cloudflared", b"one", None), ("./cloudflared", b"two", None)])
        with self.assertRaisesRegex(ValueError, "one regular"):
            start.extract_cloudflared(archive, destination)
        self.assertFalse(destination.exists())

    def test_truncated_download_preserves_existing_file_and_cleans_temporary_file(self):
        destination = self.root / "tool"
        destination.write_bytes(b"original")
        response = io.BytesIO(b"partial")
        response.headers = {"Content-Length": "100"}
        with mock.patch.object(start.urllib.request, "urlopen", return_value=response), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(OSError, "Incomplete download"):
                start.download("https://example.invalid/tool", destination)
        self.assertEqual(destination.read_bytes(), b"original")
        self.assertEqual(list(self.root.iterdir()), [destination])

    def test_checksum_mismatch_preserves_existing_file_and_cleans_temporary_file(self):
        destination = self.root / "copyparty-sfx.py"
        destination.write_bytes(b"previous verified release")
        response = io.BytesIO(b"unexpected release contents")
        response.headers = {"Content-Length": str(len(response.getvalue()))}
        expected_sha256 = hashlib.sha256(b"expected release contents").hexdigest()
        with mock.patch.object(start.urllib.request, "urlopen", return_value=response), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(OSError, "[Cc]hecksum|SHA-?256"):
                start.download("https://example.invalid/copyparty-sfx.py", destination, expected_sha256=expected_sha256)
        self.assertEqual(destination.read_bytes(), b"previous verified release")
        self.assertEqual(list(self.root.iterdir()), [destination])

    def test_verified_download_replaces_destination_atomically(self):
        destination = self.root / "copyparty-sfx.py"
        destination.write_bytes(b"old release")
        expected_body = b"verified portable release contents"
        response = io.BytesIO(expected_body)
        response.headers = {"Content-Length": str(len(expected_body))}
        with mock.patch.object(start.urllib.request, "urlopen", return_value=response), contextlib.redirect_stdout(io.StringIO()):
            start.download("https://example.invalid/copyparty-sfx.py", destination,
                           expected_sha256=hashlib.sha256(expected_body).hexdigest())
        self.assertEqual(destination.read_bytes(), expected_body)
        self.assertEqual(list(self.root.iterdir()), [destination])

    def test_prepared_portable_copyparty_is_shared_across_platforms(self):
        (self.root / "cloudflared").write_bytes(b"existing native cloudflared")

        def downloaded(url, destination, expected_sha256=None):
            destination.write_bytes(b"# portable copyparty release")

        with mock.patch.object(start, "download", side_effect=downloaded) as download:
            with mock.patch.object(start.platform, "system", return_value="Linux"), mock.patch.object(start.platform, "machine", return_value="x86_64"):
                linux_party, _ = start.ensure_tools(self.root)
            with mock.patch.object(start.platform, "system", return_value="Darwin"), mock.patch.object(start.platform, "machine", return_value="arm64"):
                mac_party, _ = start.ensure_tools(self.root)
        self.assertEqual(linux_party, [sys.executable, str(self.root / "copyparty-sfx.py")])
        self.assertEqual(mac_party, linux_party)
        self.assertEqual((self.root / "copyparty-sfx.py").read_bytes(), b"# portable copyparty release")
        self.assertEqual(download.call_count, 1)
        request = download.call_args
        self.assertIn("/releases/download/v", request.args[0])
        digest = request.kwargs.get("expected_sha256", request.args[2] if len(request.args) > 2 else None)
        self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")

    def test_existing_native_tools_are_reused_without_network(self):
        (self.root / "copyparty-sfx.py").write_text("# local copyparty", encoding="utf-8")
        (self.root / "cloudflared").write_bytes(b"local cloudflared")
        with mock.patch.object(start.platform, "system", return_value="Linux"), mock.patch.object(start.platform, "machine", return_value="x86_64"), mock.patch.object(start, "download", side_effect=AssertionError("unexpected download")):
            party, tunnel = start.ensure_tools(self.root)
        self.assertEqual(party, [sys.executable, str(self.root / "copyparty-sfx.py")])
        self.assertEqual(tunnel, [str(self.root / "cloudflared")])

    def test_an_already_executable_cloudflared_is_not_chmodded(self):
        (self.root / "copyparty-sfx.py").write_text("# local copyparty", encoding="utf-8")
        (self.root / "cloudflared").write_bytes(b"system cloudflared")
        with mock.patch.object(start.platform, "system", return_value="Linux"), mock.patch.object(start.platform, "machine", return_value="x86_64"), mock.patch.object(start.os, "access", return_value=True), mock.patch.object(start.Path, "chmod", side_effect=PermissionError("not the owner")) as chmod:
            start.ensure_tools(self.root)
        chmod.assert_not_called()

    def test_occupied_port_is_reported(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            with self.assertRaisesRegex(OSError, "already be in use"):
                start.check_port(port)

    def test_server_readiness_accepts_authenticated_http_response(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            process = mock.Mock()
            process.poll.return_value = None
            start.wait_for_server(process, server.server_port, 1, self.root / "party.log")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_server_early_exit_reports_process_log(self):
        process = mock.Mock()
        process.poll.return_value = 7
        with self.assertRaisesRegex(RuntimeError, "copyparty exited with code 7.*party.log"):
            start.wait_for_server(process, 3923, 1, self.root / "party.log")

    def test_tunnel_requires_connection_registration_not_just_url(self):
        party, tunnel = mock.Mock(), mock.Mock()
        party.poll.return_value = tunnel.poll.return_value = None
        log = self.root / "tunnel.log"
        log.write_text("https://example.trycloudflare.com\n", encoding="utf-8")
        with mock.patch.object(start.time, "sleep"), self.assertRaisesRegex(RuntimeError, "No connected tunnel"):
            start.wait_for_tunnel(party, tunnel, log, self.root / "party.log", 0.001)
        with log.open("a", encoding="utf-8") as output:
            output.write("Registered tunnel connection connIndex=0\n")
        self.assertEqual(start.wait_for_tunnel(party, tunnel, log, self.root / "party.log", 1), "https://example.trycloudflare.com")

    def test_tunnel_early_exit_is_reported(self):
        party, tunnel = mock.Mock(), mock.Mock()
        party.poll.return_value, tunnel.poll.return_value = None, 4
        log = self.root / "tunnel.log"
        log.touch()
        with self.assertRaisesRegex(RuntimeError, "cloudflared exited with code 4"):
            start.wait_for_tunnel(party, tunnel, log, self.root / "party.log", 1)

    def test_clipboard_headless_or_missing_utilities_is_nonfatal(self):
        with mock.patch.object(start.platform, "system", return_value="Linux"), mock.patch.dict(start.os.environ, {}, clear=True), mock.patch.object(start.subprocess, "run") as run:
            self.assertFalse(start.copy_to_clipboard("share"))
            run.assert_not_called()
        with mock.patch.object(start.platform, "system", return_value="Darwin"), mock.patch.object(start.shutil, "which", return_value=None):
            self.assertFalse(start.copy_to_clipboard("share"))

    def test_clipboard_timeout_falls_back_to_next_native_utility(self):
        with mock.patch.object(start.platform, "system", return_value="Linux"), mock.patch.dict(start.os.environ, {"DISPLAY": ":0"}, clear=True), mock.patch.object(start.shutil, "which", return_value="/native/tool"), mock.patch.object(start.subprocess, "run", side_effect=[subprocess.TimeoutExpired("xclip", 3), mock.Mock(returncode=0)]) as run:
            self.assertTrue(start.copy_to_clipboard("share"))
        self.assertEqual(run.call_args_list[1].args[0], ["xsel", "--clipboard", "--input"])

    def test_clipboard_windows_preserves_unicode(self):
        with mock.patch.object(start.platform, "system", return_value="Windows"), mock.patch.object(start.shutil, "which", return_value="clip.exe"), mock.patch.object(start.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(start.copy_to_clipboard("password: caf\u00e9"))
        self.assertEqual(run.call_args.kwargs["input"], "password: caf\u00e9".encode("utf-16le"))

    def test_runtime_config_is_removed_and_services_stopped_on_tunnel_failure(self):
        config = self.config()
        users = start.collect_users(config)
        (self.root / "copyparty.conf").write_text((ROOT / "copyparty.conf").read_text(encoding="utf-8-sig"), encoding="utf-8")
        party, tunnel = mock.Mock(name="party"), mock.Mock(name="tunnel")
        runtime_paths = []

        def launched(command, log, environment, cwd):
            if command[0] == "party":
                runtime_config = Path(command[command.index("-c") + 1])
                runtime_paths.append(runtime_config)
                self.assertIn("visitor: upload-secret", runtime_config.read_text(encoding="utf-8"))
                self.assertNotIn("upload-secret", command)
                self.assertEqual(environment["PYTHONUNBUFFERED"], "1")
                return party
            return tunnel

        with mock.patch.object(start, "ROOT", self.root), mock.patch.object(start, "check_port"), mock.patch.object(start, "start_process", side_effect=launched), mock.patch.object(start, "wait_for_server"), mock.patch.object(start, "wait_for_tunnel", side_effect=RuntimeError("tunnel failed")), mock.patch.object(start, "stop_process") as stop, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "tunnel failed"):
                start.run(config, users, (["party"], ["tunnel"]), 1, False)
        self.assertEqual(stop.call_args_list, [mock.call(tunnel), mock.call(party)])
        self.assertTrue(runtime_paths)
        self.assertFalse(runtime_paths[0].exists())
        self.assertFalse(runtime_paths[0].parent.exists())

    def test_clipboard_unavailable_does_not_interrupt_receiving_and_ctrl_c_cleans_up(self):
        self.settings["require_username"] = True
        config = self.config()
        users = start.collect_users(config)
        (self.root / "copyparty.conf").write_text((ROOT / "copyparty.conf").read_text(encoding="utf-8-sig"), encoding="utf-8")
        party, tunnel = mock.Mock(name="party"), mock.Mock(name="tunnel")
        party.poll.return_value = tunnel.poll.return_value = None
        output = io.StringIO()
        with mock.patch.object(start, "ROOT", self.root), mock.patch.object(start, "check_port"), mock.patch.object(start, "start_process", side_effect=[party, tunnel]), mock.patch.object(start, "wait_for_server"), mock.patch.object(start, "wait_for_tunnel", return_value="https://example.trycloudflare.com"), mock.patch.object(start, "copy_to_clipboard", return_value=False) as clipboard, mock.patch.object(start.time, "sleep", side_effect=KeyboardInterrupt), mock.patch.object(start, "stop_process") as stop, contextlib.redirect_stdout(output):
            with self.assertRaises(KeyboardInterrupt):
                start.run(config, users, (["party"], ["tunnel"]), 1, True)
        self.assertIn("Clipboard unavailable", output.getvalue())
        self.assertIn("Admin credentials", output.getvalue())
        self.assertEqual(clipboard.call_count, 1)
        copied = clipboard.call_args.args[0]
        self.assertRegex(copied, r"Username:\s+visitor\n")
        self.assertIn("upload-secret", copied)
        self.assertNotIn("operator", copied)
        self.assertNotIn("admin-secret", copied)
        self.assertEqual(stop.call_args_list, [mock.call(tunnel), mock.call(party)])

    def test_party_still_stops_if_tunnel_cleanup_raises(self):
        config = self.config()
        users = start.collect_users(config)
        (self.root / "copyparty.conf").write_text((ROOT / "copyparty.conf").read_text(encoding="utf-8-sig"), encoding="utf-8")
        party, tunnel = mock.Mock(name="party"), mock.Mock(name="tunnel")
        with mock.patch.object(start, "ROOT", self.root), mock.patch.object(start, "check_port"), mock.patch.object(start, "start_process", side_effect=[party, tunnel]), mock.patch.object(start, "wait_for_server"), mock.patch.object(start, "wait_for_tunnel", side_effect=RuntimeError("tunnel failed")), mock.patch.object(start, "stop_process", side_effect=[OSError("cleanup failed"), None]) as stop, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(OSError, "cleanup failed"):
                start.run(config, users, (["party"], ["tunnel"]), 1, False)
        self.assertEqual(stop.call_args_list, [mock.call(tunnel), mock.call(party)])

    def test_shipped_config_starts_without_prompts(self):
        config = start.load_config(ROOT / "gimmie.toml")
        self.assertEqual(config["incoming_dir"], ROOT / "incoming")
        users = start.collect_users(config)
        self.assertEqual([(user.role, user.username) for user in users], [("admin", "owner"), ("upload", "guest")])
        self.assertNotEqual(users[0].password, users[1].password)

    def test_malformed_toml_is_reported(self):
        self.config_path.write_text("port = \n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Cannot read config"):
            start.load_config(self.config_path)

    def test_prepare_skips_credentials_config_and_tunnel(self):
        with mock.patch.object(start, "ensure_tools", return_value=(["python", "party"], ["tunnel"])), mock.patch.object(start, "load_config", side_effect=AssertionError("unexpected config prompt")), mock.patch.object(start, "run", side_effect=AssertionError("unexpected tunnel")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(start.main(["--prepare"]), 0)

    def test_main_turns_terminal_close_and_sigterm_into_a_clean_stop_then_restores_handlers(self):
        if hasattr(start.signal, "SIGHUP"):
            self.assertIn(start.signal.SIGHUP, start.STOP_SIGNALS)
        self.assertIn(start.signal.SIGTERM, start.STOP_SIGNALS)
        before = {s: start.signal.getsignal(s) for s in start.STOP_SIGNALS}
        during = {}

        def tools():
            during.update({s: start.signal.getsignal(s) for s in start.STOP_SIGNALS})
            return ["python", "party"], ["tunnel"]

        with mock.patch.object(start, "ensure_tools", side_effect=tools), contextlib.redirect_stdout(io.StringIO()):
            start.main(["--prepare"])
        self.assertEqual(set(during.values()), {start.request_stop})
        self.assertEqual({s: start.signal.getsignal(s) for s in start.STOP_SIGNALS}, before)

    def test_an_inherited_signal_ignore_is_kept(self):
        previous = start.signal.signal(start.signal.SIGTERM, start.signal.SIG_IGN)
        self.addCleanup(start.signal.signal, start.signal.SIGTERM, previous)
        during = []
        with mock.patch.object(start, "ensure_tools", side_effect=lambda: during.append(start.signal.getsignal(start.signal.SIGTERM)) or (["python", "party"], ["tunnel"])), contextlib.redirect_stdout(io.StringIO()):
            start.main(["--prepare"])
        self.assertEqual(during, [start.signal.SIG_IGN], "nohup-style ignore must survive")
        self.assertIs(start.signal.getsignal(start.signal.SIGTERM), start.signal.SIG_IGN)


if __name__ == "__main__":
    unittest.main()
