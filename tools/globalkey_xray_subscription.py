from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlencode

_REMOTE_PROTOCOLS = {"vless", "hysteria"}


def extract_xray_json_links(subscription_text: str) -> list[str]:
    """Convert Happ/Xray JSON outbounds into standard share links.

    Happ subscriptions can contain an array of complete Xray configurations. The
    same outbound is commonly repeated in a combined profile and in a standalone
    profile, so connection identities are deduplicated here.
    """
    try:
        document = json.loads(subscription_text.lstrip("\ufeff"))
    except (json.JSONDecodeError, TypeError):
        return []

    if isinstance(document, dict):
        configs = [document]
    elif isinstance(document, list):
        configs = [item for item in document if isinstance(item, dict)]
    else:
        return []

    # Standalone profiles have human-friendly remarks. Process them first so
    # their names win over technical outbound tags in combined profiles.
    ordered = sorted(enumerate(configs), key=lambda item: (_remote_count(item[1]) != 1, item[0]))
    links: list[str] = []
    seen: set[str] = set()

    for _, config in ordered:
        outbounds = config.get("outbounds")
        if not isinstance(outbounds, list):
            continue
        remote_count = _remote_count(config)
        for outbound_index, outbound in enumerate(outbounds, start=1):
            if not isinstance(outbound, dict):
                continue
            protocol = str(outbound.get("protocol") or "").lower()
            if protocol not in _REMOTE_PROTOCOLS:
                continue
            fallback = f"{protocol.upper()} {outbound_index}"
            name = _node_name(config, outbound, remote_count, fallback)
            generated = (
                _vless_links(outbound, name)
                if protocol == "vless"
                else _hysteria2_links(outbound, name)
            )
            for signature, link in generated:
                if signature not in seen:
                    seen.add(signature)
                    links.append(link)
    return links


def _vless_links(outbound: dict[str, Any], name: str) -> list[tuple[str, str]]:
    settings = _dict(outbound.get("settings"))
    stream = _dict(outbound.get("streamSettings"))
    vnext_items = _list(settings.get("vnext"))
    result: list[tuple[str, str]] = []

    for vnext_index, vnext_value in enumerate(vnext_items, start=1):
        vnext = _dict(vnext_value)
        address = _string(vnext.get("address"))
        port = _valid_port(vnext.get("port"))
        if not address or port is None:
            continue
        users = _list(vnext.get("users"))
        for user_index, user_value in enumerate(users, start=1):
            user = _dict(user_value)
            uuid = _string(user.get("id"))
            if not uuid:
                continue
            node_name = name
            if len(vnext_items) > 1 or len(users) > 1:
                node_name = f"{name} {vnext_index}.{user_index}"
            query = _vless_query(user, stream)
            authority = f"{quote(uuid, safe='')}@{_format_host(address)}:{port}"
            link = f"vless://{authority}?{urlencode(query)}#{quote(node_name, safe='')}"
            signature = _signature(
                "vless",
                address,
                port,
                uuid,
                user.get("flow"),
                user.get("encryption"),
                stream.get("network"),
                stream.get("security"),
                stream.get("realitySettings"),
                stream.get("tlsSettings"),
                _transport_settings(stream),
            )
            result.append((signature, link))
    return result


def _vless_query(user: dict[str, Any], stream: dict[str, Any]) -> list[tuple[str, str]]:
    query: list[tuple[str, str]] = []
    encryption = _string(user.get("encryption")) or "none"
    query.append(("encryption", encryption))
    flow = _string(user.get("flow"))
    if flow:
        query.append(("flow", flow))

    network = (_string(stream.get("network")) or "tcp").lower()
    security = (_string(stream.get("security")) or "none").lower()
    query.extend([("security", security), ("type", network)])

    security_settings = _dict(
        stream.get("realitySettings") if security == "reality" else stream.get("tlsSettings")
    )
    _append(query, "sni", security_settings.get("serverName"))
    _append(query, "fp", security_settings.get("fingerprint"))
    if security == "reality":
        _append(query, "pbk", security_settings.get("publicKey"))
        _append(query, "sid", security_settings.get("shortId"), allow_empty=True)
        _append(query, "spx", security_settings.get("spiderX"))
    alpn = security_settings.get("alpn")
    if isinstance(alpn, list):
        _append(query, "alpn", ",".join(str(item) for item in alpn))
    elif alpn:
        _append(query, "alpn", alpn)
    if security_settings.get("allowInsecure") is True:
        query.append(("allowInsecure", "1"))

    transport = _transport_settings(stream)
    if network == "grpc":
        _append(query, "serviceName", transport.get("serviceName"), allow_empty=True)
        if transport.get("multiMode") is True:
            query.append(("mode", "multi"))
    elif network in {"ws", "httpupgrade", "xhttp", "splithttp", "http", "h2"}:
        _append(query, "path", transport.get("path"))
        host = transport.get("host")
        if not host and isinstance(transport.get("headers"), dict):
            headers = _dict(transport["headers"])
            host = headers.get("Host") or headers.get("host")
        if isinstance(host, list):
            host = host[0] if host else None
        _append(query, "host", host)
        _append(query, "mode", transport.get("mode"))
        if network in {"xhttp", "splithttp"}:
            extra = transport.get("extra")
            if isinstance(extra, dict):
                query.append(("extra", json.dumps(extra, ensure_ascii=False, separators=(",", ":"))))
    return query


def _hysteria2_links(outbound: dict[str, Any], name: str) -> list[tuple[str, str]]:
    settings = _dict(outbound.get("settings"))
    stream = _dict(outbound.get("streamSettings"))
    hysteria = _dict(stream.get("hysteriaSettings"))
    if _int_value(settings.get("version"), 2) != 2 and _int_value(hysteria.get("version"), 2) != 2:
        return []

    address = _string(settings.get("address"))
    port = _valid_port(settings.get("port"))
    auth = _string(hysteria.get("auth"))
    if not address or port is None or not auth:
        return []

    query: list[tuple[str, str]] = []
    tls = _dict(stream.get("tlsSettings"))
    _append(query, "sni", tls.get("serverName"))
    _append(query, "fp", tls.get("fingerprint"))
    alpn = tls.get("alpn")
    if isinstance(alpn, list):
        _append(query, "alpn", ",".join(str(item) for item in alpn))
    elif alpn:
        _append(query, "alpn", alpn)
    if tls.get("allowInsecure") is True:
        query.append(("insecure", "1"))

    final_mask = _dict(stream.get("finalmask"))
    quic = _dict(final_mask.get("quicParams"))
    _append(query, "up", quic.get("brutalUp"))
    _append(query, "down", quic.get("brutalDown"))
    udp_hop = _dict(quic.get("udpHop"))
    _append(query, "ports", udp_hop.get("ports"))
    _append(query, "hop-interval", udp_hop.get("interval"))
    _append(query, "bbr-profile", quic.get("bbrProfile"))

    for mask in _list(final_mask.get("udp")):
        mask_data = _dict(mask)
        mask_settings = _dict(mask_data.get("settings"))
        if mask_data.get("type") == "salamander" and mask_settings.get("password"):
            query.append(("obfs", "salamander"))
            _append(query, "obfs-password", mask_settings.get("password"))
            break

    authority = f"{quote(auth, safe='')}@{_format_host(address)}:{port}"
    suffix = f"?{urlencode(query)}" if query else ""
    link = f"hysteria2://{authority}{suffix}#{quote(name, safe='')}"
    signature = _signature("hysteria2", address, port, auth, tls, quic, final_mask.get("udp"))
    return [(signature, link)]


def _transport_settings(stream: dict[str, Any]) -> dict[str, Any]:
    network = (_string(stream.get("network")) or "tcp").lower()
    field_names = {
        "ws": ("wsSettings",),
        "grpc": ("grpcSettings",),
        "httpupgrade": ("httpupgradeSettings",),
        "xhttp": ("xhttpSettings", "splithttpSettings"),
        "splithttp": ("splithttpSettings", "xhttpSettings"),
        "http": ("httpSettings",),
        "h2": ("httpSettings", "h2Settings"),
        "tcp": ("tcpSettings",),
    }
    for field in field_names.get(network, ()):
        value = stream.get(field)
        if isinstance(value, dict):
            return value
    return {}


def _remote_count(config: dict[str, Any]) -> int:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        return 0
    return sum(
        1
        for outbound in outbounds
        if isinstance(outbound, dict)
        and str(outbound.get("protocol") or "").lower() in _REMOTE_PROTOCOLS
    )


def _node_name(
    config: dict[str, Any],
    outbound: dict[str, Any],
    remote_count: int,
    fallback: str,
) -> str:
    if remote_count == 1:
        remark = _string(config.get("remarks"))
        if remark:
            return remark
    return _string(outbound.get("tag")) or _string(config.get("remarks")) or fallback


def _signature(*parts: Any) -> str:
    return json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _append(
    query: list[tuple[str, str]],
    key: str,
    value: Any,
    *,
    allow_empty: bool = False,
) -> None:
    if value is None:
        return
    text = str(value)
    if text or allow_empty:
        query.append((key, text))


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _valid_port(value: Any) -> int | None:
    port = _int_value(value, 0)
    return port if 1 <= port <= 65535 else None


def _format_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host
