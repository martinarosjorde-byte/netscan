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
from urllib.parse import urljoin, urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


HTTPS_PORTS = {443, 8443,1024, 9443, 10443, 8006}


class HTTPScanner:
    def __init__(self, debug: bool = False, timeout_total: float = 5.0, html_preview_lines: int = 50, html_preview_chars: int = 2000):
        self.debug = debug
        self.timeout = ClientTimeout(total=timeout_total)
        self.html_preview_lines = html_preview_lines
        self.html_preview_chars = html_preview_chars


    async def scan(self, ip: str, port: int):
        is_https_port = port in HTTPS_PORTS
        scheme = "https" if is_https_port else "http"
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

        # TLS probe only if we're attempting HTTPS
        tls_probe = None
        cert_info = None

        if scheme == "https":
            if self.debug:
                print("[DEBUG][HTTPS] Running dedicated TLS probe")

            tls_probe = await self._probe_tls(ip, port)

            if tls_probe.get("success"):
                cert_info = tls_probe
            else:
                cert_info = None

            if self.debug:
                print(f"[DEBUG][HTTPS] TLS Probe Result: {tls_probe}")
        # Plain HTTP ports: simple path
        if scheme == "http":
            try:
                connector = self._build_connector_http()
                async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
                    result = await self._fetch_and_parse(session, base_url, cert_info=None)

                                
                if result and result.get("redirected_https_port"):
                    new_port = result["redirected_https_port"]

                    if self.debug:
                        print(f"[DEBUG] Redirected to HTTPS on port {new_port}, rescanning as HTTPS")

                    return await self.scan(ip, new_port)
                # 🔥 If HTTP redirected to HTTPS on custom port → rescan as HTTPS
                https_port = result.get("redirected_https_port")
                if https_port:
                    if self.debug:
                        print(f"[DEBUG] Redirected to HTTPS on port {https_port}, rescanning as HTTPS")
                    return await self.scan(ip, https_port)

                return result
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG][HTTP] Failed {base_url}/ -> {e}")
                return None

        # HTTPS strategy: modern -> (wrong version => http-on-443) -> legacy
        # 1) modern
        try:
            connector = self._build_connector_https_modern()
            async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
                result = await self._fetch_and_parse(session, base_url, cert_info)
                result["tls_http"] = "modern"
                return result

        except Exception as e_modern:
            # 2) if it's not TLS at all, try HTTP-on-443
            if tls_probe and tls_probe.get("error_type") == "not_tls":
                http_base = f"http://{ip}:{port}"
                if self.debug:
                    print(f"[DEBUG][HTTPS] TLS looks wrong on {ip}:{port}, retrying plain HTTP: {e_modern}")
                try:
                    connector = self._build_connector_http()
                    async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
                        result = await self._fetch_and_parse(session, http_base, cert_info=None)
                        result["tls_http"] = "none"
                        return result
                except Exception as e_http:
                    if self.debug:
                        print(f"[DEBUG][HTTP] Failed {http_base}/ after wrong version: {e_http}")
                    return None

            # 3) legacy TLS
            if self.debug:
                print(f"[DEBUG][HTTPS] Modern TLS failed, retrying legacy TLS: {e_modern}")

            try:
                connector = self._build_connector_https_legacy()
                async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
                    result = await self._fetch_and_parse(session, base_url, cert_info)
                    result["tls_http"] = "legacy"
                    return result
            except Exception as e_legacy:
                if self.debug:
                    print(f"[DEBUG][HTTPS] Failed {base_url}/ -> {e_legacy}")
                # 🔥 TCP fallback peek
                banner = await self._peek_tcp_banner(ip, port)

                banner_text = None
                if banner:
                    try:
                        banner_text = banner.decode(errors="ignore").strip()
                    except Exception:
                        banner_text = repr(banner)

                if self.debug and banner_text:
                    print(f"[DEBUG][TCP] Raw banner on {ip}:{port} -> {banner_text}")

                return {
                    "url": None,
                    "status": None,
                    "server": None,
                    "title": None,
                    "headers": {},
                    "cert": None,
                    "favicon_hash": None,
                    "body_preview": None,
                    "initial_body_preview": None,
                    "tls_classification": tls_probe.get("error_type") if tls_probe else None,
                    "tcp_banner": banner_text,
                }



    def _build_connector_https_modern(self) -> aiohttp.TCPConnector:
        return aiohttp.TCPConnector(ssl=self._build_ssl_ctx_modern())

    def _build_connector_https_legacy(self) -> aiohttp.TCPConnector:
        return aiohttp.TCPConnector(ssl=self._build_ssl_ctx_legacy())

    def _build_connector_http(self) -> aiohttp.TCPConnector:
        return aiohttp.TCPConnector(ssl=False)

    def _is_wrong_version(self, exc: Exception) -> bool:
        err = str(exc).upper()
        return any(x in err for x in [
            "WRONG_VERSION_NUMBER",
            "UNKNOWN_PROTOCOL",
            "HTTP_REQUEST",
        ])

    async def _fetch_and_parse(self, session: aiohttp.ClientSession, base_url: str, cert_info: dict | None):
        # base_url already includes scheme://ip:port
        if self.debug:
            scheme_upper = "HTTPS" if base_url.startswith("https://") else "HTTP"
            print(f"[DEBUG][{scheme_upper}] Requesting {base_url}/")

        resp, text = await self._fetch_text(session, f"{base_url}/")
        original_text = text

        redirect_resp, redirect_body, favicon_from_redirect, title_from_redirect, https_port = \
            await self._follow_client_redirects(session, base_url, str(resp.url), text, resp)
        
        if https_port:
            return {
                    "redirected_https_port": https_port
                }
        

        if redirect_resp:
            resp = redirect_resp
            text = redirect_body

        final_url = str(resp.url)
        status_code = resp.status
        headers = dict(resp.headers)
        server = headers.get("Server") or headers.get("server")

        if self.debug:
            self._debug_html_preview(final_url, text)

        title = self._extract_title(text) or title_from_redirect

        favicon_hash = favicon_from_redirect
        if favicon_hash is None:
            favicon_hash = await self._fetch_favicon_hash(session, base_url, text)

        if self.debug:
            scheme_upper = "HTTPS" if final_url.startswith("https") else "HTTP"
            print(f"[DEBUG][{scheme_upper}] Title: {title if title else '<none>'}")
            print(f"[DEBUG][{scheme_upper}] Cert: {cert_info if cert_info else '<none>'}")

        parsed = urlparse(final_url)

        return {
            "url": final_url,
            "redirected_https_port": (
                parsed.port if parsed.scheme == "https" and parsed.port and parsed.port not in HTTPS_PORTS else None
            ),
            "status": status_code,
            "server": server,
            "title": title,
            "headers": headers,
            "cert": cert_info if cert_info and cert_info.get("success") else None,
            "tls_classification": (
                "valid_tls"
                if cert_info and cert_info.get("success")
                else (cert_info.get("error_type") if cert_info else None)
            ),
            "favicon_hash": favicon_hash,
            "body_preview": text[:3000],
            "initial_body_preview": original_text[:3000],
        }

    async def _probe_tls(self, ip: str, port: int):
        return await asyncio.to_thread(self._probe_tls_blocking, ip, port)

    def _build_ssl_ctx_modern(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        return ctx

    def _build_ssl_ctx_legacy(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Go older (if OpenSSL allows it)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2

        # Allow weak ciphers for old appliances
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except Exception:
            pass

        # Some servers choke if TLS1.3 is even offered
        if hasattr(ssl, "OP_NO_TLSv1_3"):
            ctx.options |= ssl.OP_NO_TLSv1_3

        # ✅ Enable legacy renegotiation (OpenSSL 3.x)
        op = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
        if op:
            ctx.options |= op

        return ctx

    def _probe_tls_blocking(self, ip: str, port: int):
        versions = [
            ssl.TLSVersion.TLSv1_3,
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1_1,
            ssl.TLSVersion.TLSv1,
        ]

        last_err = None

        for v in versions:
            for allow_weak in (False, True):
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = v
                    ctx.maximum_version = v

                    if allow_weak:
                        try:
                            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
                        except Exception:
                            pass

                    op = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
                    if op:
                        ctx.options |= op

                    with socket.create_connection((ip, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=ip) as ssock:

                            der = ssock.getpeercert(binary_form=True)
                            if not der:
                                return {
                                    "success": False,
                                    "error_type": "no_certificate",
                                }

                            import hashlib
                            sha256 = hashlib.sha256(der).hexdigest()

                            try:
                                cert = x509.load_der_x509_certificate(der, default_backend())

                                try:
                                    common_name = cert.subject.get_attributes_for_oid(
                                        x509.NameOID.COMMON_NAME
                                    )[0].value
                                except Exception:
                                    common_name = None

                                try:
                                    issuer_cn = cert.issuer.get_attributes_for_oid(
                                        x509.NameOID.COMMON_NAME
                                    )[0].value
                                except Exception:
                                    issuer_cn = None

                                try:
                                    ext = cert.extensions.get_extension_for_class(
                                        x509.SubjectAlternativeName
                                    )
                                    san_list = ext.value.get_values_for_type(x509.DNSName)
                                except Exception:
                                    san_list = []

                                try:
                                    serial_number = format(cert.serial_number, "x")
                                except Exception:
                                    serial_number = None

                                try:
                                    key_size = cert.public_key().key_size
                                except Exception:
                                    key_size = None

                                signature_algorithm = (
                                    cert.signature_hash_algorithm.name
                                    if cert.signature_hash_algorithm
                                    else None
                                )

                                try:
                                    expires = cert.not_valid_after_utc.isoformat()
                                except Exception:
                                    try:
                                        expires = cert.not_valid_after.isoformat()
                                    except Exception:
                                        expires = None

                            except Exception:
                                common_name = None
                                issuer_cn = None
                                san_list = []
                                serial_number = None
                                key_size = None
                                signature_algorithm = None
                                expires = None

                            return {
                                "success": True,
                                "common_name": common_name,
                                "issuer": issuer_cn,
                                "san": san_list,
                                "serial_number": serial_number,
                                "public_key_size": key_size,
                                "signature_algorithm": signature_algorithm,
                                "expires": expires,
                                "sha256": sha256,
                                "tls_version": ssock.version(),
                                "cipher": ssock.cipher(),
                                "tls_probe": {
                                    "attempt_version": v.name,
                                    "allow_weak_ciphers": allow_weak,
                                },
                            }

                except Exception as e:
                    last_err = e
                    continue

        # Structured failure classification
        if last_err:
            err_str = str(last_err).upper()

            if "UNRECOGNIZED_NAME" in err_str:
                error_type = "sni_required"
            elif "HANDSHAKE_FAILURE" in err_str:
                error_type = "handshake_failure"
            elif "PROTOCOL_VERSION" in err_str:
                error_type = "legacy_protocol_only"
            elif "WRONG_VERSION_NUMBER" in err_str:
                error_type = "not_tls"
            elif "INTERNAL_ERROR" in err_str:
                error_type = "internal_error"
            else:
                error_type = "unknown_tls_failure"

            if self.debug:
                print(f"[DEBUG][HTTPS] TLS probe failed: {error_type} ({last_err})")

            return {
                "success": False,
                "error_type": error_type,
                "raw_error": str(last_err),
            }

        return {
            "success": False,
            "error_type": "no_response",
        }

    def _extract_title(self, html: str):
        m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if not m:
            return None
        return re.sub(r"\s+", " ", m.group(1)).strip()

    def _extract_meta_refresh_url(self, html: str):
        """
        Only match real meta refresh tags like:
        <meta http-equiv="refresh" content="1;url=/login">
        """

        pattern = re.compile(
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url\s*=\s*([^"\'>]+)',
            re.IGNORECASE
        )

        m = pattern.search(html)
        if not m:
            return None

        value = m.group(1).strip()

        # Reject JS expressions
        if any(x in value for x in ["+", "window.", "document.", "location."]):
            return None

        return value
    
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
        Only match simple literal redirects like:
        window.location = '...'
        document.location.href = "..."
        parent.location = '...'
        """

        patterns = [
            r"""parent(?:\.\w+)*\.document\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""",
            r"""top\.location\.href\s*=\s*['"]([^'"]+)['"]""",
            r"""window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""",
            r"""document\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""",
            r"""\blocation\.href\s*=\s*['"]([^'"]+)['"]""",
            r"""\blocation\s*=\s*['"]([^'"]+)['"]""",
        ]

        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                value = m.group(1).strip()

                # Reject dynamic JS expressions
                if any(x in value for x in ["+", "window.", "document.", "location."]):
                    continue

                return value

        return None
    

    async def _follow_client_redirects(
        self,
        session,
        base_url: str,
        current_url: str,
        html: str,
        resp,
        max_hops: int = 5
    ):
        """
        Follow:
        - HTTP 30x header redirects
        - meta refresh
        - simple JS redirects
        """

        url = current_url
        body = html
        favicon_hash = None
        title_intermediate = None
        visited = set([url])

        for _ in range(max_hops):

            # ---------------------------
            # 1️⃣ HTTP HEADER REDIRECT
            # ---------------------------
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if location:
                    next_url = location if location.startswith("http") else urljoin(url, location)

                    parsed = urlparse(next_url)

                    # 🔥 If redirect is HTTPS on non-standard port → stop here and signal scan()
                    if parsed.scheme == "https":
                        return resp, body, None, None, parsed.port

                    if self.debug:
                        print(f"[DEBUG][HTTP] Header redirect -> {next_url}")

                    if next_url in visited:
                        break

                    visited.add(next_url)

                    resp, body = await self._fetch_text(session, next_url)
                    url = str(resp.url)
                    continue
            # ---------------------------
            # 2️⃣ META REFRESH
            # ---------------------------
            meta = self._extract_meta_refresh_url(body)
            if meta:
                next_url = meta if meta.startswith("http") else urljoin(url, meta)

                if self.debug:
                    print(f"[DEBUG][HTTP] Meta redirect -> {next_url}")

                if next_url in visited:
                    break

                visited.add(next_url)

                resp, body = await self._fetch_text(session, next_url)
                url = str(resp.url)
                continue

            # ---------------------------
            # 3️⃣ JS REDIRECT
            # ---------------------------
            js = self._extract_js_redirect_url(body)
            if js:
                next_url = js if js.startswith("http") else urljoin(url, js)

                if self.debug:
                    print(f"[DEBUG][HTTP] JS redirect -> {next_url}")

                if next_url in visited:
                    break

                visited.add(next_url)

                resp, body = await self._fetch_text(session, next_url)
                url = str(resp.url)
                continue

            break

        return resp, body, favicon_hash, title_intermediate, None

    async def _fetch_text(self, session: aiohttp.ClientSession, url: str):
        async with session.get(url, allow_redirects=False) as resp:
            text = await resp.text(errors="ignore")

            if self.debug:
                scheme = "HTTPS" if url.startswith("https") else "HTTP"
                print(f"[DEBUG][{scheme}] {url} status={resp.status}")

            return resp, text
        
    async def _peek_tcp_banner(self, ip: str, port: int, timeout: float = 1.0, max_bytes: int = 64) -> bytes:
        """
        Connects and reads a small banner (if any) without speaking HTTP/TLS.
        Useful when 443 is actually IMAP/POP3/SMTP/etc.
        """
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            try:
                data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
                return data or b""
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            return b""
