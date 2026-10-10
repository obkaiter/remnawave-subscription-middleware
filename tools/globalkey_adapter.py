"""Extract VLESS share links; never generate a user-facing YAML configuration.

The URI and Happ/Xray extractors are copied from the supplied
MihomoKeysGenerator sources in globalkey_parsers.py and
globalkey_xray_subscription.py. The original project has no YAML *input*
parser, so the narrow YAML reader below handles VLESS proxy entries only.
"""
import hashlib
import json
import sys
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from globalkey_parsers import extract_proxy_links, parse_proxy_link


def yaml_vless_links(text):
    try:
        import yaml
        document = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(document, dict) or not isinstance(document.get("proxies"), list):
        return []
    links = []
    for proxy in document["proxies"][:1000]:
        if not isinstance(proxy, dict) or proxy.get("type") != "vless":
            continue
        try:
            allowed = {"name", "type", "server", "port", "uuid", "udp", "network", "tls", "servername", "client-fingerprint", "alpn", "reality-opts", "ws-opts", "grpc-opts", "xhttp-opts", "flow", "encryption", "skip-cert-verify"}
            if set(proxy) - allowed or proxy.get("skip-cert-verify") is True:
                continue
            server, port, uuid = str(proxy["server"]), int(proxy["port"]), str(proxy["uuid"])
            if not server or not 1 <= port <= 65535 or not uuid:
                continue
            network = str(proxy.get("network") or "tcp").lower()
            if network not in {"tcp", "ws", "grpc", "xhttp"}:
                continue
            query = {"type": network, "encryption": str(proxy.get("encryption") or "none")}
            if proxy.get("flow"):
                query["flow"] = str(proxy["flow"])
            if proxy.get("tls"):
                reality = proxy.get("reality-opts") or {}
                if not isinstance(reality, dict) or set(reality) - {"public-key", "short-id", "spider-x"}:
                    continue
                query["security"] = "reality" if isinstance(proxy.get("reality-opts"), dict) else "tls"
                query["sni"] = str(proxy.get("servername") or "")
                query["fp"] = str(proxy.get("client-fingerprint") or "")
                if isinstance(proxy.get("alpn"), list):
                    query["alpn"] = ",".join(str(v) for v in proxy["alpn"])
                if reality:
                    query["pbk"] = str(reality.get("public-key") or "")
                    query["sid"] = str(reality.get("short-id") or "")
                    query["spx"] = str(reality.get("spider-x") or "")
            elif proxy.get("reality-opts"):
                continue
            opts = proxy.get(network + "-opts") or {}
            if network == "ws":
                opts = proxy.get("ws-opts") or {}
                if not isinstance(opts, dict) or set(opts) - {"path", "headers"} or set(opts.get("headers") or {}) - {"Host"}:
                    continue
                query["path"] = str(opts.get("path") or "")
                query["host"] = str((opts.get("headers") or {}).get("Host") or "")
            elif network == "grpc":
                if not isinstance(opts, dict) or set(opts) - {"grpc-service-name"}:
                    continue
                query["serviceName"] = str(opts.get("grpc-service-name") or "")
            elif network == "xhttp":
                query["path"] = str(opts.get("path") or "")
                query["host"] = str(opts.get("host") or "")
                if opts.get("mode"):
                    query["mode"] = str(opts["mode"])
                # Unknown XHTTP extras can be critical. Reject rather than lose them.
                if set(opts) - {"path", "host", "mode"}:
                    continue
            host = f"[{server}]" if ":" in server and not server.startswith("[") else server
            links.append(f"vless://{quote(uuid, safe='')}@{host}:{port}?{urlencode(query)}#{quote(str(proxy.get('name') or 'VLESS'), safe='')}")
        except (TypeError, ValueError, KeyError, AttributeError):
            continue
    return links


def extract(text):
    links = extract_proxy_links(text) + yaml_vless_links(text)
    found = {}
    rejected = 0
    skipped = {}
    for link in links[:2000]:
        if len(link) > 8192:
            rejected += 1
            continue
        if not link.lower().startswith("vless://"):
            rejected += 1
            scheme = link.partition(":")[0].lower()
            try:
                parse_proxy_link(link)
                status = "unsupported_for_target"
            except Exception:
                status = "invalid"
            digest = hashlib.sha256(link.encode()).hexdigest()
            skipped.setdefault(digest, {"fingerprint": digest, "name": scheme.upper(), "uri": "", "status": status, "reason": scheme})
            continue
        try:
            proxy = parse_proxy_link(link)
            known_query = {"type", "security", "flow", "encryption", "sni", "serverName", "alpn", "fp", "pbk", "sid", "spx", "pqv", "pcs", "vcn", "headerType", "allowInsecure", "path", "host", "serviceName", "mode", "seed", "mtu", "tti", "extra", "fm"}
            if set(parse_qs(urlsplit(link).query, keep_blank_values=True)) - known_query:
                digest = hashlib.sha256(link.encode()).hexdigest()
                skipped.setdefault(digest, {"fingerprint": digest, "name": "VLESS", "uri": "", "status": "unsupported_for_target", "reason": "unknown_uri_parameters"})
                rejected += 1
                continue
            # Exact technical identity includes all parsed connection options.
            technical = {k: v for k, v in proxy.items() if k != "name"}
            digest = hashlib.sha256(json.dumps(technical, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            found.setdefault(digest, {"fingerprint": digest, "uri": link, "name": str(proxy["name"])[:191]})
        except Exception:
            rejected += 1
            digest = hashlib.sha256(link.encode()).hexdigest()
            skipped.setdefault(digest, {"fingerprint": digest, "name": "VLESS", "uri": "", "status": "invalid", "reason": "invalid_uri"})
    return {"nodes": list(found.values()), "skipped": list(skipped.values()), "rejected": rejected, "found": len(links)}


if __name__ == "__main__":
    body = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        sys.exit(2)
    print(json.dumps(extract(body.decode("utf-8-sig", errors="replace")), ensure_ascii=False))
