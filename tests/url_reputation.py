#!/usr/bin/env python
"""
url_reputation.py - URL Reputation test.
Tests access to known bad/malicious URLs.
Python 3.5.2 compatible.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

PRESETS = [
    ("safebrowsing-malware", "Google Safe Browsing Malware Test", "http://malware.testing.google.test/testing/malware/"),
    ("safebrowsing-phish", "Google Safe Browsing Phishing Test", "http://phishing.testing.google.test/testing/phishing/"),
    ("avsvmcloud", "SUNBURST C2 Domain", "http://avsvmcloud.com"),
    ("websitetheme", "Known Malicious Domain", "http://websitetheme.com"),
    ("phishing-1", "Phishing Domain (linkedopports)", "http://linkedopports.com"),
    ("python-release", "Malicious Library Delivery", "http://python-release.com"),
]


def main():
    parser = helpers.base_parser("URL Reputation Test")
    args = parser.parse_args()

    helpers.emit_header("URL Reputation Test")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    start = time.time()

    for key, label, url in targets:
        status, body, err = helpers.http_get(url, timeout=args.timeout,
                                             no_verify=args.no_verify)
        verdict, detail = helpers.classify_web_response(status, body, err)
        helpers.emit_result(verdict, label, detail)
        total += 1
        if verdict == "BLOCKED":
            blocked += 1
        elif verdict == "ALLOWED":
            allowed += 1
        else:
            inconclusive += 1
        time.sleep(0.5)

    for custom_url in custom:
        label = "[custom] %s" % custom_url
        status, body, err = helpers.http_get(custom_url, timeout=args.timeout,
                                             no_verify=args.no_verify)
        verdict, detail = helpers.classify_web_response(status, body, err)
        helpers.emit_result(verdict, label, detail)
        total += 1
        if verdict == "BLOCKED":
            blocked += 1
        elif verdict == "ALLOWED":
            allowed += 1
        else:
            inconclusive += 1
        time.sleep(0.5)

    elapsed = time.time() - start
    helpers.emit_done(total, blocked, allowed, inconclusive, elapsed)


if __name__ == "__main__":
    main()
