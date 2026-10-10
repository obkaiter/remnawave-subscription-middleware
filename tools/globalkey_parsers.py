from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from globalkey_xray_subscription import extract_xray_json_links

SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2")
_LINK_PATTERN = re.compile(
    rf"(?i)(?:{'|'.join(SUPPORTED_SCHEMES)})://[^\s<>\"']+"
)
_REALITY_PUBLIC_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_TRUE_VALUES = {"1", "true", "yes", "on"}
# This XHTTP/REALITY endpoint repeatedly fails to parse in the target Xray
# client, even though the current feed encodes its headers as an empty object.
_KNOWN_XHTTP_CLIENT_FAILURES = {
    ("178.72.167.151", 443, "54p7hD_YYV5f2ATL7rTBk4NG_KhStO76-1_tSKmXah8")
}


class ProxyParseError(ValueError):
    """A proxy link is malformed or unsupported."""


def extract_proxy_links(subscription_text: str) -> list[str]:
    """Extract proxy URIs from plain text, base64, or Happ/Xray JSON."""
    variants = [subscription_text.lstrip("\ufeff")]
    decoded = _decode_subscription_base64(subscription_text)
    if decoded is not None:
        variants.append(decoded)

    links: list[str] = []
    seen: set[str] = set()
    for text in variants:
        for match in _LINK_PATTERN.finditer(text):
            link = match.group(0).rstrip(",;])}")
            if link not in seen:
                seen.add(link)
                links.append(link)
    for link in extract_xray_json_links(subscription_text):
        if link not in seen:
            seen.add(link)
            links.append(link)
    return links


def parse_proxy_links(links: Iterable[str]) -> tuple[list[dict[str, Any]], list[str]]:
    proxies, errors, _ = _parse_proxy_links(links)
    return proxies, errors


def _parse_proxy_links(
    links: Iterable[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    proxies: list[dict[str, Any]] = []
    errors: list[str] = []
    valid_links: list[str] = []
    used_names: set[str] = set()

    for index, link in enumerate(links, start=1):
        try:
            proxy = parse_proxy_link(link, index)
            _reject_known_xhttp_client_failure(proxy)
            proxy["name"] = _unique_name(str(proxy["name"]), used_names)
            proxies.append(proxy)
            valid_links.append(link)
        except (ProxyParseError, ValueError, TypeError, binascii.Error) as error:
            scheme = link.partition(":")[0].lower() or "unknown"
            errors.append(f"link {index} ({scheme}): {error}")
    return proxies, errors, valid_links


def parse_proxy_link(link: str, index: int = 1) -> dict[str, Any]:
    scheme = link.partition(":")[0].lower()
    if scheme == "vless":
        return _parse_vless(link, index)
    if scheme == "vmess":
        return _parse_vmess(link, index)
    if scheme == "trojan":
        return _parse_trojan(link, index)
    if scheme == "ss":
        return _parse_shadowsocks(link, index)
    if scheme in {"hysteria2", "hy2"}:
        return _parse_hysteria2(link, index)
    raise ProxyParseError(f"unsupported scheme: {scheme}")


def _reject_known_xhttp_client_failure(proxy: dict[str, Any]) -> None:
    if proxy.get("type") != "vless" or proxy.get("network") != "xhttp":
        return
    reality = proxy.get("reality-opts")
    if not isinstance(reality, dict):
        return
    identity = (
        proxy.get("server"),
        proxy.get("port"),
        reality.get("public-key"),
    )
    if identity in _KNOWN_XHTTP_CLIENT_FAILURES:
        raise ProxyParseError(
            "XHTTP/REALITY node is excluded after repeated client startup failures"
        )


def _parse_vless(link: str, index: int) -> dict[str, Any]:
    parsed = _split_url(link)
    query = _query(parsed.query)
    if query.get("security", "").lower() == "reality":
        _validate_reality_public_keys(parsed.query)
    server = _hostname(parsed)
    security = query.get("security", "").lower()
    raw_encryption = query.get("encryption")
    encryption = raw_encryption if raw_encryption is not None else ""
    if raw_encryption is not None and not _is_valid_vless_encryption(encryption):
        raise ProxyParseError(
            "unsupported VLESS encryption; expected 'none' or a valid "
            "mlkem768x25519plus value"
        )
    has_transport_security = security in {"tls", "reality", "xtls"}
    has_vless_encryption = bool(encryption and encryption != "none")
    if (
        not has_transport_security
        and not has_vless_encryption
        and not _is_private_host(server)
    ):
        raise ProxyParseError(
            "unencrypted VLESS to a public address requires TLS, REALITY, "
            "or VLESS Encryption"
        )
    uuid = unquote(parsed.username or "")
    if not uuid:
        raise ProxyParseError("missing UUID")

    network = _network(query)
    proxy: dict[str, Any] = {
        "name": _name(parsed.fragment, f"VLESS {index}"),
        "type": "vless",
        "server": server,
        "port": _port(parsed),
        "uuid": uuid,
        "udp": True,
        "network": network,
        "packet-encoding": query.get("packetEncoding", "xudp"),
    }
    flow = query.get("flow")
    if flow:
        proxy["flow"] = flow
    encryption = query.get("encryption")
    if encryption and encryption != "none":
        proxy["encryption"] = encryption

    _apply_tls(proxy, query, trojan=False)
    _apply_transport(proxy, query, network)
    return proxy


def _is_valid_vless_encryption(value: str) -> bool:
    """Match the VLESS encryption values accepted by current Xray-core."""
    if value == "none":
        return True

    parts = value.split(".")
    if (
        len(parts) < 4
        or parts[0] != "mlkem768x25519plus"
        or parts[1] not in {"native", "xorpub", "random"}
        or parts[2] not in {"1rtt", "0rtt"}
    ):
        return False

    for part in parts[3:]:
        # Xray treats short components as padding; long components must be
        # URL-safe Base64 encodings of an X25519 or ML-KEM public key.
        if len(part) < 20:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_-]+", part):
            return False
        try:
            decoded = base64.b64decode(
                part + "=" * (-len(part) % 4), altchars=b"-_", validate=True
            )
        except (binascii.Error, ValueError):
            return False
        if len(decoded) not in {32, 1184}:
            return False
    return True


def _parse_vmess(link: str, index: int) -> dict[str, Any]:
    payload = link.split("://", 1)[1].split("#", 1)[0]
    try:
        data = json.loads(_b64decode(payload).decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as error:
        raise ProxyParseError("invalid VMess base64 JSON") from error
    if not isinstance(data, dict):
        raise ProxyParseError("VMess payload must be a JSON object")

    server = str(data.get("add") or "").strip()
    uuid = str(data.get("id") or "").strip()
    if not server or not uuid:
        raise ProxyParseError("missing server or UUID")
    try:
        port = int(data.get("port"))
    except (TypeError, ValueError) as error:
        raise ProxyParseError("invalid port") from error

    network = str(data.get("net") or "tcp").lower()
    proxy: dict[str, Any] = {
        "name": str(data.get("ps") or f"VMess {index}"),
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": _safe_int(data.get("aid"), 0),
        "cipher": str(data.get("scy") or "auto"),
        "udp": True,
        "network": network,
    }
    query = {
        "security": str(data.get("tls") or "none"),
        "sni": str(data.get("sni") or data.get("host") or ""),
        "alpn": str(data.get("alpn") or ""),
        "fp": str(data.get("fp") or ""),
        "allowInsecure": str(data.get("allowInsecure") or ""),
        "insecure": str(data.get("insecure") or ""),
        "host": str(data.get("host") or ""),
        "path": str(data.get("path") or ""),
        "serviceName": str(data.get("path") or data.get("serviceName") or ""),
        "headerType": str(data.get("type") or ""),
    }
    _apply_tls(proxy, query, trojan=False)
    _apply_transport(proxy, query, network)
    return proxy


def _parse_trojan(link: str, index: int) -> dict[str, Any]:
    parsed = _split_url(link)
    query = _query(parsed.query)
    password = unquote(parsed.username or "")
    if not password:
        raise ProxyParseError("missing password")
    network = _network(query)
    proxy: dict[str, Any] = {
        "name": _name(parsed.fragment, f"Trojan {index}"),
        "type": "trojan",
        "server": _hostname(parsed),
        "port": _port(parsed),
        "password": password,
        "udp": True,
        "network": network,
    }
    security = query.get("security", "tls").lower()
    if security != "none":
        _apply_tls(proxy, {**query, "security": security}, trojan=True)
    _apply_transport(proxy, query, network)
    return proxy


def _parse_shadowsocks(link: str, index: int) -> dict[str, Any]:
    value = link.split("://", 1)[1]
    before_fragment, _, fragment = value.partition("#")
    main, _, query_string = before_fragment.partition("?")

    if "@" in main:
        credentials, endpoint = main.rsplit("@", 1)
        credentials = unquote(credentials)
        if ":" not in credentials:
            credentials = _b64decode(credentials).decode("utf-8")
        method, separator, password = credentials.partition(":")
        if not separator:
            raise ProxyParseError("invalid Shadowsocks credentials")
        endpoint_url = urlsplit(f"ss://x@{endpoint}")
        server = _hostname(endpoint_url)
        port = _port(endpoint_url)
    else:
        try:
            decoded = _b64decode(main).decode("utf-8")
        except (UnicodeDecodeError, binascii.Error) as error:
            raise ProxyParseError("invalid Shadowsocks base64 payload") from error
        credentials, separator, endpoint = decoded.rpartition("@")
        if not separator:
            raise ProxyParseError("missing Shadowsocks endpoint")
        method, separator, password = credentials.partition(":")
        if not separator:
            raise ProxyParseError("invalid Shadowsocks credentials")
        endpoint_url = urlsplit(f"ss://x@{endpoint}")
        server = _hostname(endpoint_url)
        port = _port(endpoint_url)

    proxy: dict[str, Any] = {
        "name": _name(fragment, f"Shadowsocks {index}"),
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": unquote(method),
        "password": unquote(password),
        "udp": True,
    }
    plugin = _query(query_string).get("plugin")
    if plugin:
        _apply_ss_plugin(proxy, plugin)
    return proxy


def _parse_hysteria2(link: str, index: int) -> dict[str, Any]:
    parsed = _split_url(link)
    query = _query(parsed.query)
    _reject_insecure_tls(query)
    password = unquote(parsed.username or "")
    if not password:
        raise ProxyParseError("missing password")
    proxy: dict[str, Any] = {
        "name": _name(parsed.fragment, f"Hysteria2 {index}"),
        "type": "hysteria2",
        "server": _hostname(parsed),
        "port": _port(parsed),
        "password": password,
    }
    sni = query.get("sni") or query.get("peer")
    if sni:
        proxy["sni"] = sni
    obfs = query.get("obfs")
    obfs_password = query.get("obfs-password") or query.get("obfsParam")
    if obfs:
        proxy["obfs"] = obfs
    if obfs_password:
        proxy["obfs-password"] = obfs_password
    if query.get("alpn"):
        proxy["alpn"] = _csv(query["alpn"])
    fingerprint = query.get("fp") or query.get("fingerprint")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    for source, target in (
        ("up", "up"),
        ("down", "down"),
        ("ports", "ports"),
        ("hop-interval", "hop-interval"),
        ("bbr-profile", "bbr-profile"),
    ):
        if query.get(source):
            proxy[target] = query[source]
    return proxy


def _apply_tls(proxy: dict[str, Any], query: dict[str, str], *, trojan: bool) -> None:
    security = query.get("security", "").lower()
    tls_enabled = security in {"tls", "reality", "xtls"} or (
        proxy["type"] == "vmess" and security == "tls"
    )
    if not tls_enabled:
        return
    _reject_insecure_tls(query)
    proxy["tls"] = True
    server_name = query.get("sni") or query.get("serverName")
    if server_name:
        proxy["sni" if trojan else "servername"] = server_name
    if query.get("alpn"):
        proxy["alpn"] = _csv(query["alpn"])
    fingerprint = query.get("fp") or query.get("fingerprint")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    if security == "reality":
        public_key = query.get("pbk") or query.get("publicKey")
        short_id = query.get("sid") or query.get("shortId")
        reality: dict[str, Any] = {}
        if public_key:
            reality["public-key"] = public_key
        if short_id is not None:
            reality["short-id"] = short_id
        spider_x = query.get("spx")
        if spider_x and not spider_x.startswith("/"):
            raise ProxyParseError(
                "invalid REALITY spiderX: expected an empty value or a path "
                "starting with '/'"
            )
        if spider_x is not None:
            reality["spider-x"] = spider_x
        # Xray-core 26.9.8+ requires the hybrid X25519MLKEM768 key share.
        # Mihomo removes it unless this option is enabled, which makes an
        # otherwise valid REALITY node fail with a connection timeout. Keep an
        # explicit URI override for compatibility with old REALITY servers.
        mlkem = query.get("support-x25519mlkem768")
        reality["support-x25519mlkem768"] = (
            _as_bool(mlkem) if mlkem is not None else True
        )
        if reality:
            proxy["reality-opts"] = reality


def _apply_transport(proxy: dict[str, Any], query: dict[str, str], network: str) -> None:
    path = query.get("path")
    host = query.get("host")
    if network == "ws":
        opts: dict[str, Any] = {}
        if path:
            clean_path, early_data = _extract_early_data(path)
            opts["path"] = clean_path
            if early_data is not None:
                opts["max-early-data"] = early_data
                opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
        if host:
            opts["headers"] = {"Host": host}
        if query.get("type", "").lower() == "httpupgrade":
            opts["v2ray-http-upgrade"] = True
            opts["v2ray-http-upgrade-fast-open"] = True
        if opts:
            proxy["ws-opts"] = opts
    elif network == "grpc":
        proxy["grpc-opts"] = {
            "grpc-service-name": query.get("serviceName") or query.get("service") or ""
        }
    elif network in {"http", "h2"}:
        raise ProxyParseError(
            "legacy HTTP transport was removed from current Xray-core; "
            "the node was skipped"
        )
    elif network == "xhttp":
        opts = {}
        if path:
            opts["path"] = path
        if host:
            opts["host"] = host
        if query.get("mode"):
            opts["mode"] = query["mode"]
        _apply_xhttp_extra(opts, query.get("extra"))
        if opts:
            proxy["xhttp-opts"] = opts


def _apply_xhttp_extra(opts: dict[str, Any], raw_extra: str | None) -> None:
    if not raw_extra:
        return
    try:
        extra = json.loads(raw_extra)
    except json.JSONDecodeError as error:
        raise ProxyParseError("invalid XHTTP extra JSON") from error
    if extra is None:
        return
    if not isinstance(extra, dict):
        raise ProxyParseError("XHTTP extra must be a JSON object")
    if "headers" in extra:
        headers = extra["headers"]
        if headers is not None:
            if not isinstance(headers, dict):
                raise ProxyParseError(
                    "XHTTP extra.headers must be an object of string values; "
                    "arrays are unsupported"
                )
            if any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in headers.items()
            ):
                raise ProxyParseError(
                    "XHTTP extra.headers must be an object of string values"
                )
            opts["headers"] = headers
    field_map = {
        "noGRPCHeader": "no-grpc-header",
        "xPaddingBytes": "x-padding-bytes",
        "xPaddingObfsMode": "x-padding-obfs-mode",
        "xPaddingKey": "x-padding-key",
        "xPaddingHeader": "x-padding-header",
        "xPaddingPlacement": "x-padding-placement",
        "xPaddingMethod": "x-padding-method",
        "uplinkHTTPMethod": "uplink-http-method",
        "sessionIDPlacement": "session-placement",
        "sessionIDKey": "session-key",
        "sessionIDTable": "session-table",
        "sessionIDLength": "session-length",
        "seqPlacement": "seq-placement",
        "seqKey": "seq-key",
        "uplinkDataPlacement": "uplink-data-placement",
        "uplinkDataKey": "uplink-data-key",
        "uplinkChunkSize": "uplink-chunk-size",
        "scMaxEachPostBytes": "sc-max-each-post-bytes",
        "scMinPostsIntervalMs": "sc-min-posts-interval-ms",
        "scStreamUpServerSecs": "sc-stream-up-server-secs",
    }
    for source, target in field_map.items():
        if source in extra:
            opts[target] = extra[source]


def _apply_ss_plugin(proxy: dict[str, Any], plugin_value: str) -> None:
    parts = plugin_value.split(";")
    plugin = parts[0]
    options: dict[str, Any] = {}
    for item in parts[1:]:
        key, separator, value = item.partition("=")
        options[key] = value if separator else True
    if plugin in {"obfs-local", "simple-obfs"}:
        proxy["plugin"] = "obfs"
        proxy["plugin-opts"] = {
            "mode": options.get("obfs", "http"),
            "host": options.get("obfs-host", ""),
        }
    elif plugin == "v2ray-plugin":
        proxy["plugin"] = "v2ray-plugin"
        proxy["plugin-opts"] = {
            "mode": "websocket",
            "host": options.get("host", ""),
            "path": options.get("path", ""),
            "tls": "tls" in options,
        }


def _network(query: dict[str, str]) -> str:
    value = (query.get("type") or query.get("net") or query.get("network") or "tcp").lower()
    if value == "httpupgrade":
        return "ws"
    if value == "splithttp":
        return "xhttp"
    return value


def _split_url(link: str):
    try:
        parsed = urlsplit(link)
        _ = parsed.port
        return parsed
    except ValueError as error:
        raise ProxyParseError(f"invalid URL: {error}") from error


def _hostname(parsed: Any) -> str:
    if not parsed.hostname:
        raise ProxyParseError("missing server")
    return parsed.hostname


def _port(parsed: Any) -> int:
    if parsed.port is None or not 1 <= parsed.port <= 65535:
        raise ProxyParseError("missing or invalid port")
    return parsed.port


def _is_private_host(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        normalized = host.rstrip(".").lower()
        private_suffixes = (
            ".localhost",
            ".local",
            ".internal",
            ".home.arpa",
            ".test",
            ".example",
            ".invalid",
        )
        return (
            "." not in normalized
            or normalized == "localhost"
            or normalized.endswith(private_suffixes)
        )
    return address.is_private or address.is_loopback or address.is_link_local


def _query(value: str) -> dict[str, str]:
    return {key: values[-1] for key, values in parse_qs(value, keep_blank_values=True).items()}


def _validate_reality_public_keys(query: str) -> None:
    parameters = parse_qs(query, keep_blank_values=True)
    public_keys = parameters.get("pbk", []) + parameters.get("publicKey", [])
    if not public_keys:
        raise ProxyParseError("missing REALITY public key")

    for public_key in public_keys:
        if not _is_valid_reality_public_key(public_key):
            raise ProxyParseError(
                "invalid REALITY public key: expected 43-character unpadded "
                "base64url encoding of 32 bytes"
            )


def _is_valid_reality_public_key(value: str) -> bool:
    if not _REALITY_PUBLIC_KEY_PATTERN.fullmatch(value):
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return False
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    return len(decoded) == 32 and canonical == value


def _name(fragment: str, fallback: str) -> str:
    return unquote(fragment).strip() or fallback


def _unique_name(name: str, used: set[str]) -> str:
    base = name
    suffix = 2
    while name in used:
        name = f"{base} ({suffix})"
        suffix += 1
    used.add(name)
    return name


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _as_bool(value: str | None) -> bool:
    return bool(value and value.lower() in _TRUE_VALUES)


def _reject_insecure_tls(query: dict[str, str]) -> None:
    if _as_bool(query.get("allowInsecure")) or _as_bool(query.get("insecure")):
        raise ProxyParseError(
            "TLS certificate verification is disabled with allowInsecure/insecure, "
            "which current Xray-core rejects"
        )


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_early_data(path: str) -> tuple[str, int | None]:
    marker = "?ed="
    if marker not in path:
        return path, None
    clean_path, value = path.split(marker, 1)
    try:
        return clean_path, int(value.split("/", 1)[0])
    except ValueError:
        return path, None


def _decode_subscription_base64(text: str) -> str | None:
    compact = "".join(text.split())
    if not compact or "://" in compact:
        return None
    try:
        decoded = _b64decode(compact).decode("utf-8-sig")
    except (UnicodeDecodeError, binascii.Error):
        return None
    return decoded if _LINK_PATTERN.search(decoded) else None


def _b64decode(value: str) -> bytes:
    compact = "".join(value.split())
    padded = compact + "=" * (-len(compact) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)
