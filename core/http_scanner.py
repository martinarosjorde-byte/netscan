# HTTPScanner: Asynchronous HTTP/HTTPS scanner with support for meta-refresh and JavaScript redirects, favicon hashing, and certificate info extraction. Designed for use in a larger port scanning framework.
# core/http_scanner.py

import asyncio
import re
import ssl
import socket
import base64
import mmh3
import aiohttp
from aiohttp import ClientTimeout
from urllib.parse import urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


HTTPS_PORTS = {443, 8443, 9443, 10443, 8006}


class HTTPScanner:
    def __init__(self, debug: bool = False, timeout_total: float = 5.0, html_preview_lines: int = 50, html_preview_chars: int = 2000):
        self.debug = debug
        self.timeout = ClientTimeout(total=timeout_total)
        self.html_preview_lines = html_preview_lines
        self.html_preview_chars = html_preview_chars


    async def scan(self, ip: str, port: int):
        scheme = "https" if port in HTTPS_PORTS else "http"
        scheme_upper = scheme.upper()
        base_url = f"{scheme}://{ip}:{port}"

        rdns = None
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        if self.debug:
            print("\n[DEBUG] ===========================")
            print("[DEBUG] Starting HTTP scan")
            print(f"[DEBUG] IP: {ip}")
            print(f"[DEBUG] Reverse DNS: {rdns}")
            print(f"[DEBUG] Port: {port}")
            print(f"[DEBUG] Scheme: {scheme}")
            print("[DEBUG] ===========================")

        # -------------------------
        # TLS Probe
        # -------------------------
        cert_info = None
        if scheme == "https":
            if self.debug:
                print("[DEBUG][HTTPS] Running dedicated TLS probe")

            cert_info = await self._probe_tls(ip, port)

            if self.debug:
                print(f"[DEBUG][HTTPS] TLS Probe Result: {cert_info if cert_info else '<none>'}")

        # -------------------------
        # HTTP Request
        # -------------------------
        if scheme == "https":
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        else:
            connector = aiohttp.TCPConnector()

        try:
            async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:

                if self.debug:
                    print(f"[DEBUG][{scheme_upper}] Requesting {base_url}/")

                resp, text = await self._fetch_text(session, f"{base_url}/")
                original_text = text

                # Follow meta/JS redirects
                redirect_resp, redirect_body, favicon_from_redirect, title_from_redirect = \
                    await self._follow_client_redirects(
                        session, base_url, str(resp.url), text
                    )

                if redirect_resp:
                    resp = redirect_resp
                    text = redirect_body

                final_url = str(resp.url)
                status_code = resp.status
                headers = dict(resp.headers)
                server = headers.get("Server") or headers.get("server")

                # Debug preview
                if self.debug:
                    self._debug_html_preview(final_url, text)

                # Extract title
                title = self._extract_title(text) or title_from_redirect

                # Extract favicon
                favicon_hash = favicon_from_redirect
                if favicon_hash is None:
                    favicon_hash = await self._fetch_favicon_hash(session, base_url, text)

                if self.debug:
                    print(f"[DEBUG][{scheme_upper}] Title: {title if title else '<none>'}")
                    print(f"[DEBUG][{scheme_upper}] Cert: {cert_info if cert_info else '<none>'}")

                return {
                    "url": final_url,
                    "status": status_code,
                    "server": server,
                    "title": title,
                    "headers": headers,
                    "cert": cert_info,
                    "favicon_hash": favicon_hash,
                    "body_preview": text[:3000], 
                    "initial_body_preview": original_text[:3000],
                }

        except Exception as e:
            if self.debug:
                print(f"[DEBUG][{scheme_upper}] Failed {base_url}/ -> {e}")
            return None

    async def _probe_tls(self, ip: str, port: int):
        return await asyncio.to_thread(self._probe_tls_blocking, ip, port)


    def _probe_tls_blocking(self, ip: str, port: int):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:

                    der = ssock.getpeercert(binary_form=True)
                    if not der:
                        return None

                    import hashlib
                    sha256 = hashlib.sha256(der).hexdigest()

                    # -------------------------
                    # Parse certificate using cryptography
                    # -------------------------
                    cert = x509.load_der_x509_certificate(der, default_backend())

                    # CN
                    common_name = None
                    try:
                        common_name = cert.subject.get_attributes_for_oid(
                            x509.NameOID.COMMON_NAME
                        )[0].value
                    except Exception:
                        pass

                    # Issuer CN
                    issuer_cn = None
                    try:
                        issuer_cn = cert.issuer.get_attributes_for_oid(
                            x509.NameOID.COMMON_NAME
                        )[0].value
                    except Exception:
                        pass

                    # SAN
                    san_list = []
                    try:
                        ext = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        san_list = ext.value.get_values_for_type(x509.DNSName)
                    except Exception:
                        pass

                    # Serial number
                    serial_number = format(cert.serial_number, "x")

                    # Public key size
                    public_key = cert.public_key()
                    key_size = None
                    try:
                        key_size = public_key.key_size
                    except Exception:
                        pass

                    # Signature algorithm
                    signature_algorithm = cert.signature_hash_algorithm.name \
                        if cert.signature_hash_algorithm else None

                    return {
                        "common_name": common_name,
                        "issuer": issuer_cn,
                        "san": san_list,
                        "serial_number": serial_number,
                        "public_key_size": key_size,
                        "signature_algorithm": signature_algorithm,
                        "expires": cert.not_valid_after_utc.isoformat(),
                        "sha256": sha256,
                        "tls_version": ssock.version(),
                        "cipher": ssock.cipher(),
                    }

        except Exception as e:
            if self.debug:
                print(f"[DEBUG][HTTPS] TLS probe failed: {e}")
            return None


    def _extract_title(self, html: str):
        m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if not m:
            return None
        return re.sub(r"\s+", " ", m.group(1)).strip()

    def _extract_meta_refresh_url(self, html: str):
        m = re.search(
            r'http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url\s*=\s*([^"\'>]+)',
            html, re.IGNORECASE
        )
        if not m:
            m = re.search(r'URL\s*=\s*([^"\'>]+)', html, re.IGNORECASE)
        return m.group(1).strip() if m else None

    def _debug_html_preview(self, url: str, html: str):
        scheme = "HTTPS" if url.startswith("https") else "HTTP"
        print(f"[DEBUG][{scheme}] HTML preview from {url}:")
        if not html:
            print(f"[DEBUG][{scheme}] <empty body>")
            return

        # prefer "first N lines", but cap by chars so it doesn't spam
        lines = html.splitlines()
        preview_lines = lines[: self.html_preview_lines]
        preview = "\n".join(preview_lines)

        if len(preview) > self.html_preview_chars:
            preview = preview[: self.html_preview_chars] + "\n...[truncated]..."

        # print with indentation to make it readable
        for ln in preview.splitlines():
            print(f"[DEBUG][{scheme}] {ln}")

    async def _fetch_favicon_hash(self, session: aiohttp.ClientSession, base_url: str, html: str):
        # Find favicon link more robustly
        favicon_path = None
        
        # Look for all <link> tags
        for link_tag in re.finditer(r'<link[^>]*>', html, re.IGNORECASE):
            tag = link_tag.group(0)
            
            # Check if this link has rel="icon" or rel="shortcut icon"
            rel_match = re.search(r'rel=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if rel_match and 'icon' in rel_match.group(1).lower():
                # Found an icon link, now extract href
                href_match = re.search(r'href=["\']([^"\']+)["\']', tag)
                if href_match:
                    favicon_path = href_match.group(1).strip()
                    break
        
        favicon_path = favicon_path or "/favicon.ico"
        favicon_url = favicon_path if favicon_path.startswith("http") else f"{base_url}/{favicon_path.lstrip('/')}"

        try:
            async with session.get(favicon_url, allow_redirects=True) as resp:
                if self.debug:
                    scheme = "HTTPS" if favicon_url.startswith("https") else "HTTP"
                    print(f"[DEBUG][{scheme}] Favicon URL: {favicon_url} status={resp.status}")

                if resp.status != 200:
                    if self.debug:
                        scheme = "HTTPS" if favicon_url.startswith("https") else "HTTP"
                        print(f"[DEBUG][{scheme}] Favicon not 200 -> no hash")
                    return None

                body = await resp.read()
                if not body:
                    if self.debug:
                        scheme = "HTTPS" if favicon_url.startswith("https") else "HTTP"
                        print(f"[DEBUG][{scheme}] Favicon empty body -> no hash")
                    return None

                encoded = base64.b64encode(body)
                return mmh3.hash(encoded)

        except Exception as e:
            if self.debug:
                scheme = "HTTPS" if base_url.startswith("https") else "HTTP"
                print(f"[DEBUG][{scheme}] Favicon fetch failed: {e}")
            return None

    async def _get_cert_info(self, ip: str, port: int):
        return await asyncio.to_thread(self._get_cert_info_blocking, ip, port)

    def _get_cert_info_blocking(self, ip: str, port: int):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                san = []
                for typ, val in cert.get("subjectAltName", []) or []:
                    san.append(f"{typ}:{val}")

                return {
                    "common_name": subject.get("commonName"),
                    "issuer": issuer.get("commonName"),
                    "expires": cert.get("notAfter"),
                    "san": san,
                }
            



    def _extract_js_redirect_url(self, html: str):
        """
        Detect very common patterns:
        top.location.href='/Main_Login.asp';
        window.location='/x';
        location.href="/x";
        document.location = '/x';
        Returns the URL/path string or None.
        """
        patterns = [
            r"""top\.location\.href\s*=\s*['"]([^'"]+)['"]""",
            r"""window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""",
            r"""location\.href\s*=\s*['"]([^'"]+)['"]""",
            r"""document\.location\s*=\s*['"]([^'"]+)['"]""",
            r"""\blocation\s*=\s*['"]([^'"]+)['"]""",
        ]
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return None


    async def _follow_client_redirects(self, session, base_url: str, current_url: str, html: str, max_hops: int = 2):
        """
        Follow meta-refresh and simple JS redirects a couple of times.
        Returns: (final_resp, final_html, favicon_hash_from_intermediate, title_from_intermediate)
        """
        url = current_url
        body = html
        resp = None
        favicon_hash = None  # Track favicon from intermediate pages
        title_intermediate = None  # Track title from intermediate pages

        for _ in range(max_hops):
            meta = self._extract_meta_refresh_url(body)
            js = self._extract_js_redirect_url(body)

            next_target = meta or js
            if not next_target:
                break

            # DEBUG: Show HTML preview and title for the page with the redirect
            if self.debug:
                self._debug_html_preview(url, body)
                title = self._extract_title(body)
                scheme = "HTTPS" if url.startswith("https") else "HTTP"
                print(f"[DEBUG][{scheme}] Title: {title if title else '<none>'}")

            # Extract favicon and title from this intermediate page (if not already found)
            if favicon_hash is None:
                favicon_hash = await self._fetch_favicon_hash(session, base_url, body)
            
            if title_intermediate is None:
                title_intermediate = self._extract_title(body)

            next_url = next_target if next_target.startswith("http") else urljoin(url, next_target)

            if self.debug:
                scheme = "HTTPS" if next_url.startswith("https") else "HTTP"
                kind = "Meta" if meta else "JS"
                print(f"[DEBUG][{scheme}] {kind} redirect -> {next_url}")

            resp, body = await self._fetch_text(session, next_url)
            url = str(resp.url)

        # if we never redirected, resp stays None; caller already has first resp
        return resp, body, favicon_hash, title_intermediate
    
    async def _fetch_text(self, session: aiohttp.ClientSession, url: str):
        async with session.get(url, allow_redirects=True) as resp:
            text = await resp.text(errors="ignore")

            if self.debug:
                scheme = "HTTPS" if url.startswith("https") else "HTTP"
                print(f"[DEBUG][{scheme}] {url} status={resp.status}")

            return resp, text