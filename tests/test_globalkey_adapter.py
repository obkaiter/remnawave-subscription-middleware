import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from globalkey_adapter import extract


ONE = "vless://123e4567-e89b-12d3-a456-426614174001@one.example.org:443?security=tls&type=ws&path=%2Fone#Same"
TWO = "vless://123e4567-e89b-12d3-a456-426614174002@two.example.org:443?security=tls&type=ws&path=%2Ftwo#Same"


class AdapterTests(unittest.TestCase):
    def test_sources_sum_and_exact_dedup(self):
        first = extract(ONE + "\n" + TWO)
        second = extract(ONE)
        merged = {n["fingerprint"]: n for result in (first, second) for n in result["nodes"]}
        self.assertEqual(len(merged), 2)
        self.assertEqual(extract(ONE + "\n" + TWO), first)

    def test_base64(self):
        encoded = base64.b64encode((ONE + "\n" + TWO).encode()).decode()
        self.assertEqual(len(extract(encoded)["nodes"]), 2)

    def test_xray_json(self):
        data = {"outbounds": [{"protocol": "vless", "tag": "node", "settings": {"vnext": [{"address": "one.example.org", "port": 443, "users": [{"id": "123e4567-e89b-12d3-a456-426614174001", "encryption": "none"}]}]}, "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/one"}}}]}
        self.assertEqual(len(extract(json.dumps(data))["nodes"]), 1)

    def test_yaml_reads_only_proxies(self):
        text = """proxies:
  - name: Safe
    type: vless
    server: one.example.org
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174001
    tls: true
    network: ws
    ws-opts: {path: /one}
proxy-groups: [{name: Evil, type: select, proxies: [Safe]}]
rules: [MATCH,Evil]
dns: {enable: true}
"""
        result = extract(text)
        self.assertEqual(len(result["nodes"]), 1)
        self.assertNotIn("rules", result["nodes"][0])

    def test_other_protocol_is_not_published(self):
        result = extract("trojan://password@one.example.org:443#Other")
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(result["skipped"][0]["status"], "unsupported_for_target")

    def test_unknown_parameter_cannot_be_lost_in_xray(self):
        result = extract(ONE.replace("&path=", "&packetEncoding=xudp&path="))
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["skipped"][0]["reason"], "unknown_uri_parameters")


if __name__ == "__main__":
    unittest.main()
