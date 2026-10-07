#!/usr/bin/env python3
"""Static checks for website/: security rules, links, accessibility basics, launch blockers.

    python3 scripts/check_site.py            # fail on real problems; list launch blockers
    python3 scripts/check_site.py --launch   # also fail while any REPLACE_* placeholder remains

Standard library only. These are the same rules the Content-Security-Policy in website/_headers
enforces in the browser, so a pass here means the page works under it.
"""
import datetime as dt
import os
import re
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
SITE = Path(os.environ.get("SITE_DIR") or ROOT / "website")
RENDER_YAML = Path(os.environ.get("RENDER_YAML") or ROOT / "render.yaml")
MAX_FILE_BYTES = 100 * 1024 * 1024  # keep deploys lean; installers live in downloads/

errors: list[str] = []
warnings: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


# ---------------------------------------------------------------- URLs

def own_hosts() -> set[str]:
    """Hosts that count as 'this site': the placeholder, plus whatever the canonical says."""
    hosts = {"REPLACE_DOMAIN"}
    index = SITE / "index.html"
    if index.exists():
        match = re.search(r'<link[^>]+rel="canonical"[^>]+href="([^"]+)"', index.read_text(encoding="utf-8"))
        if match and urlparse(match.group(1)).hostname:
            hosts.add(urlparse(match.group(1)).hostname)
    return hosts


# The only third-party host the site may load anything from: the live Product Hunt badge image.
THIRD_PARTY_IMG_HOSTS = {"api.producthunt.com"}


def is_external(url: str, hosts: set[str]) -> bool:
    url = url.strip()
    if url.startswith("//"):
        return True
    parsed = urlparse(url)
    if parsed.scheme in ("", "mailto"):
        return False
    return parsed.hostname not in hosts


def local_target(url: str) -> Path | None:
    """Map a site-relative URL to a file, honouring Cloudflare Pages clean URLs."""
    url = url.strip()
    if "REPLACE_" in url or url.startswith(("#", "mailto:", "//")):
        return None
    parsed = urlparse(url)
    if parsed.scheme:
        return None
    path = parsed.path
    if not path:
        return None
    base = SITE / path.lstrip("/")
    for candidate in (base, base.with_name(base.name + ".html"), base / "index.html"):
        if candidate.is_file():
            return candidate
    return base  # does not exist; caller reports it


# ---------------------------------------------------------------- HTML

RESOURCE_ATTRS = {
    "img": ("src", "srcset"), "source": ("src", "srcset"), "video": ("src", "poster"),
    "audio": ("src",), "track": ("src",), "link": ("href", "imagesrcset"),
}
FORBIDDEN_TAGS = {"script", "style", "iframe", "object", "embed", "form", "base", "applet", "frame", "frameset"}


class Page(HTMLParser):
    def __init__(self, name: str):
        super().__init__(convert_charrefs=True)
        self.name = name
        self.h1 = 0
        self.has_main = False
        self.has_lang = False
        self.has_canonical = False
        self.ids: list[str] = []
        self.anchors: list[dict] = []
        self.resources: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        names = [k for k, _ in attrs]
        for dup in {n for n in names if names.count(n) > 1}:
            err(f"{self.name}: <{tag}> repeats attribute {dup} (browsers keep the first, parsers differ)")
        a = {k: (v or "") for k, v in attrs}
        if tag == "html" and a.get("lang"):
            self.has_lang = True
        if tag == "h1":
            self.h1 += 1
        if tag == "main":
            self.has_main = True
        if tag in FORBIDDEN_TAGS:
            err(f"{self.name}: <{tag}> is not allowed (blocked by CSP / needless attack surface)")
        if tag == "meta" and a.get("http-equiv", "").lower() in ("refresh", "set-cookie", "content-security-policy"):
            err(f"{self.name}: <meta http-equiv={a['http-equiv']}> is not allowed")
        if "style" in a:
            err(f"{self.name}: inline style attribute on <{tag}> (blocked by style-src 'self')")
        for attr in a:
            if attr.startswith("on"):
                err(f"{self.name}: inline event handler {attr} on <{tag}>")
        if "id" in a:
            self.ids.append(a["id"])
        if tag == "link" and a.get("rel") == "canonical":
            self.has_canonical = True
        if tag == "a" and "href" in a:
            self.anchors.append(a)
        if tag == "img":
            if "alt" not in a:
                err(f"{self.name}: <img src={a.get('src')}> has no alt attribute")
            if not (a.get("width") and a.get("height")):
                err(f"{self.name}: <img src={a.get('src')}> lacks width/height (layout shift)")
        if tag == "meta" and a.get("content", "").startswith(("http://", "https://", "//")):
            self.resources.append(("meta", a["content"]))
        for attr in RESOURCE_ATTRS.get(tag, ()):
            value = a.get(attr, "")
            if not value:
                continue
            if attr.endswith("srcset"):
                for candidate in value.split(","):
                    if candidate.strip():
                        self.resources.append((tag, candidate.strip().split()[0]))
            else:
                self.resources.append((tag, value))


def check_pages(hosts: set[str]) -> None:
    pages = sorted(SITE.glob("*.html"))
    if not pages:
        err("no HTML pages found in website/")
    for page in pages:
        text = page.read_text(encoding="utf-8")
        parser = Page(page.name)
        parser.feed(text)
        if not parser.has_lang:
            err(f"{page.name}: <html> has no lang attribute")
        if parser.h1 != 1:
            err(f"{page.name}: expected exactly one <h1>, found {parser.h1}")
        if not parser.has_main:
            err(f"{page.name}: no <main> landmark")
        if page.name != "404.html" and not parser.has_canonical:
            err(f"{page.name}: no canonical link")
        dupes = {i for i in parser.ids if parser.ids.count(i) > 1}
        if dupes:
            err(f"{page.name}: duplicate id(s): {', '.join(sorted(dupes))}")

        for tag, url in parser.resources:
            if is_external(url, hosts) and not (tag == "img" and urlparse(url).scheme == "https"
                                                 and urlparse(url).hostname in THIRD_PARTY_IMG_HOSTS):
                err(f"{page.name}: <{tag}> loads an external resource: {url}")
            target = local_target(url)
            if target is not None and not target.exists():
                err(f"{page.name}: missing local file for <{tag}>: {url}")

        for a in parser.anchors:
            href = a["href"].strip()
            parsed = urlparse(href)
            rel = set(a.get("rel", "").split())
            if parsed.scheme == "javascript" or parsed.scheme == "data":
                err(f"{page.name}: {parsed.scheme}: URL in link: {href}")
            external = is_external(href, hosts) and parsed.scheme not in ("mailto",)
            if (external or a.get("target") == "_blank") and not {"noopener", "noreferrer"} <= rel:
                err(f"{page.name}: external/_blank link without rel=\"noopener noreferrer\": {href}")
            if href.startswith("#"):
                if href[1:] and href[1:] not in parser.ids:
                    err(f"{page.name}: link to missing anchor {href}")
                continue
            target = local_target(href)
            if target is not None and not target.exists():
                err(f"{page.name}: broken local link: {href}")


# ---------------------------------------------------------------- CSS / SVG

def check_css() -> None:
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    if re.search(r"@import", css, re.I):
        err("styles.css uses @import")
    if re.search(r"url\(\s*['\"]?\s*(https?:)?//", css, re.I):
        err("styles.css loads an external URL")
    if re.search(r"expression\(|javascript:|(?<![\w-])behavior\s*:", css, re.I):
        err("styles.css contains an executable construct")
    if ":focus-visible" not in css:
        err("styles.css defines no :focus-visible style")
    if "prefers-reduced-motion" not in css:
        err("styles.css ignores prefers-reduced-motion")


def check_svgs() -> None:
    for svg in SITE.rglob("*.svg"):
        body = svg.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"<\s*(script|foreignObject|use|image|a)\b|\son\w+\s*=|href\s*=\s*[\"']\s*(https?:)?//", body, re.I):
            err(f"{svg.relative_to(SITE)} contains script, foreignObject, use/image/a, or an external reference")


# ---------------------------------------------------------------- render.yaml headers

def parse_render_headers() -> dict[str, list[tuple[str, str]]]:
    """Reads the `headers:` list of the first service in render.yaml (plain text, no YAML library).

    Expected shape, one key per line:
        headers:
          - path: /*
            name: X-Frame-Options
            value: DENY
    """
    rules: dict[str, list[tuple[str, str]]] = {}
    in_headers = False
    base_indent = 0
    entry: dict[str, str] = {}

    def flush() -> None:
        if {"path", "name", "value"} <= entry.keys():
            rules.setdefault(entry["path"], []).append((entry["name"], entry["value"]))
        entry.clear()

    for raw in RENDER_YAML.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        text = raw.strip()
        if not in_headers:
            if text == "headers:":
                in_headers, base_indent = True, indent
            continue
        if indent <= base_indent and not text.startswith("- "):
            flush()
            break
        if indent <= base_indent:  # a "- " at the same indent as `headers:` would be malformed
            flush()
            break
        if text.startswith("- "):
            flush()
            text = text[2:]
        key, _, value = text.partition(":")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        entry[key.strip()] = value
    flush()
    return rules


def check_headers() -> None:
    if not RENDER_YAML.exists():
        err("render.yaml is missing (response headers are defined there)")
        return
    rules = parse_render_headers()
    if "/*" not in rules:
        err("render.yaml has no headers for /*")
        return
    glob = rules["/*"]
    names = [n.lower() for n, _ in glob]
    by_name = {n.lower(): v for n, v in glob}
    for n in set(names):
        if names.count(n) > 1:
            err(f"render.yaml /*: {n} is set more than once")

    csp = by_name.get("content-security-policy")
    if not csp:
        err("render.yaml /* has no Content-Security-Policy")
    else:
        directives: dict[str, list[str]] = {}
        for part in csp.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            if tokens[0] in directives:
                err(f"CSP repeats {tokens[0]} (browsers use the first)")
            directives.setdefault(tokens[0], tokens[1:])
        expected = {
            "default-src": ["'none'"], "script-src": ["'none'"], "style-src": ["'self'"],
            "img-src": ["'self'"] + [f"https://{h}" for h in sorted(THIRD_PARTY_IMG_HOSTS)], "font-src": ["'self'"], "media-src": ["'self'"],
            "manifest-src": ["'self'"], "connect-src": ["'none'"], "frame-src": ["'none'"],
            "object-src": ["'none'"], "worker-src": ["'none'"], "base-uri": ["'none'"],
            "form-action": ["'none'"], "frame-ancestors": ["'none'"],
        }
        for name, want in expected.items():
            if directives.get(name) != want:
                err(f"CSP {name} must be {' '.join(want)}, is {directives.get(name)}")
        if "upgrade-insecure-requests" not in directives:
            err("CSP lacks upgrade-insecure-requests")
        for name, tokens in directives.items():
            for token in tokens:
                if token not in ("'none'", "'self'") and not (
                        name == "img-src" and token in {f"https://{h}" for h in THIRD_PARTY_IMG_HOSTS}):
                    err(f"CSP {name} allows {token}")

    for header in ("strict-transport-security", "x-content-type-options", "x-frame-options",
                   "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
                   "cross-origin-resource-policy"):
        if header not in by_name:
            err(f"render.yaml /* is missing {header}")
    hsts = by_name.get("strict-transport-security", "")
    match = re.search(r"max-age=(\d+)", hsts)
    if not match or int(match.group(1)) < 31536000:
        err("HSTS max-age must be at least 31536000")
    if "includeSubDomains" in hsts or "preload" in hsts:
        warnings.append("HSTS has includeSubDomains/preload: keep only once every subdomain serves HTTPS")
    if by_name.get("x-content-type-options", "").lower() != "nosniff":
        err("X-Content-Type-Options must be nosniff")
    if "DENY" not in by_name.get("x-frame-options", "").upper():
        err("X-Frame-Options must be DENY")

    for pattern, headers in rules.items():
        for name, value in headers:
            if name.lower() == "access-control-allow-origin":
                err(f"render.yaml {pattern}: sets Access-Control-Allow-Origin")
            if pattern != "/*" and name.lower() in names:
                err(f"render.yaml {pattern}: repeats the /* header {name}")


# ---------------------------------------------------------------- files, meta

def check_files() -> None:
    banned_names = {".git", ".DS_Store", "_worker.js", "functions", "node_modules"}
    banned_suffixes = {".map", ".bak", ".orig", ".swp", ".js", ".mjs", ".pem", ".key", ".p12", ".zip"}
    for path in SITE.rglob("*"):
        rel = path.relative_to(SITE)
        if path.name in banned_names or path.name.startswith(".env") or path.name.endswith("~") \
                or path.suffix.lower() in banned_suffixes:
            err(f"deploy directory contains {rel}")
        if path.suffix.lower() == ".dmg" and rel.parts[0] != "downloads":
            err(f"{rel}: installers belong in website/downloads/")
        if path.name == "_headers":
            err("website/_headers is Cloudflare-only and would be published as a file; headers live in render.yaml")
        if path.is_file() and path.stat().st_size > MAX_FILE_BYTES:
            err(f"{rel} is over the 25 MiB Pages limit (host big files elsewhere)")
    for required in ("404.html", "robots.txt", "sitemap.xml", ".well-known/security.txt", "favicon.svg"):
        if not (SITE / required).exists():
            err(f"missing {required}")

    sec = SITE / ".well-known/security.txt"
    if sec.exists():
        text = sec.read_text()
        if not re.search(r"^Contact:\s*\S+", text, re.M):
            err("security.txt has no Contact field")
        expires = re.search(r"^Expires:\s*(\S+)", text, re.M)
        if not expires:
            err("security.txt has no Expires field (RFC 9116)")
        else:
            try:
                when = dt.datetime.fromisoformat(expires.group(1).replace("Z", "+00:00"))
                now = dt.datetime.now(dt.timezone.utc)
                if when <= now:
                    err("security.txt has expired")
                elif when - now >= dt.timedelta(days=365):
                    err("security.txt Expires must be less than a year away (RFC 9116)")
                elif when - now < dt.timedelta(days=30):
                    warnings.append("security.txt expires within 30 days")
            except ValueError:
                err("security.txt Expires is not an ISO 8601 date")

    robots = SITE / "robots.txt"
    if robots.exists() and "Sitemap:" not in robots.read_text():
        err("robots.txt has no Sitemap line")


def check_appcast(hosts: set[str]) -> None:
    """If an update feed has been published, make sure every entry is signed and hosted here."""
    path = SITE / "appcast.xml"
    if not path.exists():
        warnings.append("no appcast.xml yet: the app has no update feed until scripts/appcast.sh runs")
        return
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        err(f"appcast.xml is not valid XML: {exc}")
        return
    sparkle = "{http://www.andymatuschak.org/xml-namespaces/sparkle}"
    items = root.findall(".//item")
    if not items:
        err("appcast.xml has no <item> entries")
    for item in items:
        enclosure = item.find("enclosure")
        if enclosure is None:
            err("appcast.xml: an item has no <enclosure>")
            continue
        url = enclosure.get("url", "")
        if urlparse(url).scheme != "https" or urlparse(url).hostname not in hosts:
            err(f"appcast.xml: enclosure is not an https URL on this site: {url}")
        if not enclosure.get(sparkle + "edSignature"):
            err(f"appcast.xml: enclosure has no EdDSA signature: {url}")
        target = local_target(urlparse(url).path)
        if target is not None and not target.exists():
            err(f"appcast.xml: enclosure file is missing from the site: {url}")


def check_sitemap(hosts: set[str]) -> None:
    path = SITE / "sitemap.xml"
    if not path.exists():
        return
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        err(f"sitemap.xml is not valid XML: {exc}")
        return
    for loc in (el.text or "" for el in root.iter() if el.tag.endswith("loc")):
        parsed = urlparse(loc.strip())
        if parsed.hostname not in hosts:
            err(f"sitemap.xml lists a URL outside this site: {loc}")
            continue
        target = local_target(parsed.path or "/")
        if parsed.path in ("", "/"):
            target = SITE / "index.html"
        if target is not None and not target.exists():
            err(f"sitemap.xml lists a page that does not exist: {loc}")


# ---------------------------------------------------------------- contrast

def luminance(hex_value: str) -> float:
    r, g, b = (int(hex_value[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def check_contrast() -> None:
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    declared = re.findall(r"--([a-z-]+):\s*([^;]+);", css)
    tokens: dict[str, str] = {}
    for name, value in declared:
        value = value.strip()
        if re.fullmatch(r"#[0-9a-fA-F]{6}", value):
            tokens[name] = value
        elif value.startswith("#"):
            err(f"colour token --{name} is not a 6-digit hex ({value}); contrast can't be checked")
    pairs = [("ink", "base", 4.5), ("ink-soft", "base", 4.5), ("muted", "base", 4.5),
             ("blue-text", "base", 4.5), ("edge-strong", "base", 3.0)]
    for fg, bg, minimum in pairs:
        if fg not in tokens or bg not in tokens:
            err(f"contrast check needs tokens --{fg} and --{bg}")
            continue
        value = ratio(tokens[fg], tokens[bg])
        if value < minimum:
            err(f"contrast {fg} on {bg} is {value:.2f}:1, need {minimum}:1")
    if "blue" in tokens and ratio("#ffffff", tokens["blue"]) < 4.5:
        err(f"white on --blue is {ratio('#ffffff', tokens['blue']):.2f}:1, need 4.5:1 (button label)")
    leftovers = re.findall(r"(?<!--)(?<![\w-])color:\s*(#[0-9a-fA-F]{3,6})", css)
    for colour in leftovers:
        if colour.lower() not in ("#fff", "#ffffff"):
            warnings.append(f"hard-coded text colour {colour} in styles.css is not contrast-checked")


# ---------------------------------------------------------------- placeholders

def placeholders() -> list[str]:
    found: dict[str, set[str]] = {}
    for path in SITE.rglob("*"):
        if path.is_file() and path.suffix in (".html", ".txt", ".xml", ".css", ".svg", ""):
            for token in set(re.findall(r"REPLACE_[A-Z0-9_]+", path.read_text(encoding="utf-8", errors="ignore"))):
                found.setdefault(token, set()).add(path.relative_to(SITE).as_posix())
    for extra in (RENDER_YAML, ROOT / "project.yml"):
        if extra.exists():
            for token in set(re.findall(r"REPLACE_[A-Z0-9_]+", extra.read_text(encoding="utf-8"))):
                found.setdefault(token, set()).add(extra.name)
    return [f"{token}  ({', '.join(sorted(files))})" for token, files in sorted(found.items())]


def main() -> int:
    launch = "--launch" in sys.argv
    hosts = own_hosts()
    check_pages(hosts)
    check_css()
    check_svgs()
    check_headers()
    check_files()
    check_appcast(hosts)
    check_sitemap(hosts)
    check_contrast()
    blockers = placeholders()

    for w in warnings:
        print(f"warn  {w}")
    for e in errors:
        print(f"FAIL  {e}")
    if blockers:
        print("\nLaunch blockers (replace before deploying):")
        for b in blockers:
            print(f"  - {b}")
    print(f"\n{len(errors)} problem(s), {len(blockers)} placeholder(s)")
    if errors or (launch and blockers):
        return 1
    print("site checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
