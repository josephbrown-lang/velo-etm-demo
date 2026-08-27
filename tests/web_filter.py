#!/usr/bin/env python
"""
web_filter.py - Web/URL Filter test.
Tests access to known gambling, social media, and news sites.
Python 3.5.2 compatible.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers

PRESETS = [
    ("https://www.coral.co.uk", "Coral", "https://www.coral.co.uk"),
    ("https://www.fanduel.com", "FanDuel", "https://www.fanduel.com"),
    ("https://www.ladbrokes.com", "Ladbrokes", "https://www.ladbrokes.com"),
    ("https://www.sportsbet.com.au", "Sportsbet AU", "https://www.sportsbet.com.au"),
    ("https://www.bwin.com", "Bwin", "https://www.bwin.com"),
    ("https://www.888casino.com", "888 Casino", "https://www.888casino.com"),
    ("https://www.leovegas.com", "LeoVegas", "https://www.leovegas.com"),
    ("https://www.casumo.com", "Casumo", "https://www.casumo.com"),
    ("https://www.mrgreen.com", "Mr Green", "https://www.mrgreen.com"),
    ("https://www.ggpoker.com", "GGPoker", "https://www.ggpoker.com"),
    ("https://www.partypoker.com", "partypoker", "https://www.partypoker.com"),
    ("https://www.thelotter.com", "theLotter", "https://www.thelotter.com"),
    ("https://www.facebook.com", "Facebook", "https://www.facebook.com"),
    ("https://www.youtube.com", "YouTube", "https://www.youtube.com"),
    ("https://www.cnn.com", "CNN", "https://www.cnn.com"),
    ("https://www.reddit.com", "Reddit", "https://www.reddit.com"),
]


def main():
    parser = helpers.base_parser("Web/URL Filter Test")
    args = parser.parse_args()

    helpers.emit_header("Web/URL Filter Test")

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
        time.sleep(0.3)

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
        time.sleep(0.3)

    elapsed = time.time() - start
    helpers.emit_done(total, blocked, allowed, inconclusive, elapsed)


if __name__ == "__main__":
    main()
