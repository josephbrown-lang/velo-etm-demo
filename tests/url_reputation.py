#!/usr/bin/env python
"""
url_reputation.py - URL Reputation test.
Tests access to known bad/malicious URLs, grouped by risk level.
Python 3.5.2 compatible.
"""

import sys
import os
import time
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

LEVEL_ORDER = [
    "High Risk",
    "Suspicious",
    "Moderate Risk",
    "Low Risk",
    "Trustworthy",
    "Unknown",
]

PRESETS = [
    # High Risk - known malware/phishing test URLs
    ("safebrowsing-malware", "Google Safe Browsing Malware Test", "http://testsafebrowsing.appspot.com/s/malware.html", "High Risk"),
    ("safebrowsing-phish", "Google Safe Browsing Phishing Test", "http://testsafebrowsing.appspot.com/s/phishing.html", "High Risk"),
    ("wicar-malware", "WICAR Malware Test File", "http://malware.wicar.org/data/eicar.com", "High Risk"),
    ("wicar-cryptominer", "WICAR Cryptominer Page", "http://malware.wicar.org/data/js_crypto_miner.html", "High Risk"),
    ("mcafee-highrisk", "McAfee High Risk Test", "http://www.testingmcafeesites.com/testreputation_highrisk.html", "High Risk"),
    ("mcafee-red", "McAfee Red Verdict Test", "http://www.testingmcafeesites.com/testrep_red.html", "High Risk"),

    # Suspicious
    ("amtso-phishing", "AMTSO Phishing Test Page", "https://www.amtso.org/feature-settings-check-phishing-page/", "Suspicious"),
    ("amtso-pua", "AMTSO PUA Test Page", "https://www.amtso.org/feature-settings-check-potentially-unwanted-applications/", "Suspicious"),
    ("mcafee-gray", "McAfee Unverified/Gray Test", "http://www.testingmcafeesites.com/testrep_gray.html", "Suspicious"),

    # Moderate Risk
    ("wicar-site", "WICAR Test Site", "http://www.wicar.org", "Moderate Risk"),
    ("mcafee-yellow", "McAfee Medium/Yellow Test", "http://www.testingmcafeesites.com/testrep_yellow.html", "Moderate Risk"),

    # Low Risk
    ("amtso-site", "AMTSO Security Org", "http://amtso.org", "Low Risk"),

    # Trustworthy - control group (should never be blocked)
    ("google", "Google (control)", "https://www.google.com", "Trustworthy"),
    ("microsoft", "Microsoft (control)", "https://www.microsoft.com", "Trustworthy"),
]


def _group_by_level(targets):
    """Group targets into an OrderedDict keyed by risk level."""
    groups = OrderedDict()
    for level in LEVEL_ORDER:
        groups[level] = []
    for entry in targets:
        level = entry[3] if len(entry) > 3 else "Unknown"
        if level not in groups:
            groups[level] = []
        groups[level].append(entry)
    return groups


def main():
    parser = helpers.base_parser("URL Reputation Test")
    parser.add_argument('--flat', action='store_true',
                        help='Disable grouping by risk level')
    args = parser.parse_args()

    helpers.emit_header("URL Reputation Test")

    targets, custom = helpers.filter_targets(PRESETS, args.target)

    total = 0
    blocked = 0
    allowed = 0
    inconclusive = 0
    level_stats = {}
    start = time.time()

    if args.flat:
        run_order = targets
    else:
        groups = _group_by_level(targets)
        run_order = []
        for level in LEVEL_ORDER:
            entries = groups.get(level, [])
            if entries:
                run_order.append(("__level__", level))
            run_order.extend(entries)

    for entry in run_order:
        if entry[0] == "__level__":
            level_name = entry[1]
            helpers.emit_info("--- %s ---" % level_name)
            continue

        key, label, url = entry[0], entry[1], entry[2]
        level = entry[3] if len(entry) > 3 else "Unknown"

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

        if level not in level_stats:
            level_stats[level] = {"blocked": 0, "allowed": 0, "inconclusive": 0}
        if verdict == "BLOCKED":
            level_stats[level]["blocked"] += 1
        elif verdict == "ALLOWED":
            level_stats[level]["allowed"] += 1
        else:
            level_stats[level]["inconclusive"] += 1

        time.sleep(0.5)

    if custom:
        if not args.flat:
            helpers.emit_info("--- Custom ---")
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

    if not args.flat and level_stats:
        helpers.emit_info("")
        helpers.emit_info("Per-level summary:")
        for level in LEVEL_ORDER:
            if level in level_stats:
                s = level_stats[level]
                helpers.emit_info("  %s: %d blocked, %d allowed, %d inconclusive" % (
                    level, s["blocked"], s["allowed"], s["inconclusive"]))

    elapsed = time.time() - start
    helpers.emit_done(total, blocked, allowed, inconclusive, elapsed)


if __name__ == "__main__":
    main()
