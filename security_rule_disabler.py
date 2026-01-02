#!/usr/bin/env python3
"""
This is a Palo Alto Panorama hygiene script that disables security rules generated to CSV file from the Policy Optimizer tool.

User Guide:
1. Generate a CSV file from the target Device Group using the Policy Optimizer tool, with headers matching this structre:
 - Rule UUID
 - Name
 - Tags 
 - Source Zone
 - Source Address
 - Destination Zone
 - Destination Address
 - Action
 - Rule Usage Hit Count
 - Rule Usage Last Hit
 - Rule Usage First Hit
 - Rule Usage Reset Date
 - Modified
 - Created
2. Move downloaded file to the same directory of the script
3. Run the script and specify user configuration variables

Features:
- Logs progress to the console and generates a report of the disabled rules a CSV file 
- Rate limits the number of API writen to the Panorama, this helps prevent overloading the Panorama CPU

"""

import csv
import getpass
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional

from panos.panorama import Panorama


# ──────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────
def setup_logging() -> Tuple[logging.Logger, str]:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.abspath(f"disable_panorama_rules_{ts}.log")

    logger = logging.getLogger("panorama_rule_disabler")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)

    logger.addHandler(sh)
    logger.addHandler(fh)

    logger.info("Logging initialized")
    logger.info("Log file: %s", log_path)
    return logger, log_path


# ──────────────────────────────────────────────────────────────────
# RATE LIMITER
# ──────────────────────────────────────────────────────────────────
class WriteRateLimiter:
    """
    Python side:
    - Controls how frequently XAPI 'set' calls are made

    Panorama side:
    - Prevents CPU spikes caused by rapid config writes
    """

    def __init__(
        self,
        logger: logging.Logger,
        max_writes_before_pause: int,
        pause_seconds: float,
        min_seconds_between_writes: float,
    ):
        self.logger = logger
        self.max_writes_before_pause = max_writes_before_pause
        self.pause_seconds = pause_seconds
        self.min_seconds_between_writes = min_seconds_between_writes

        self.write_count = 0
        self._last_write_ts: Optional[float] = None

    def before_write(self):
        # Enforce minimum spacing between writes
        if self.min_seconds_between_writes and self._last_write_ts is not None:
            elapsed = time.time() - self._last_write_ts
            if elapsed < self.min_seconds_between_writes:
                time.sleep(self.min_seconds_between_writes - elapsed)

        # Pause after N writes if configured
        if self.max_writes_before_pause and self.write_count > 0:
            if self.write_count % self.max_writes_before_pause == 0:
                self.logger.info(
                    "Rate limit reached (%d writes). Pausing for %s seconds...",
                    self.write_count,
                    self.pause_seconds,
                )
                time.sleep(self.pause_seconds)

    def after_write(self):
        self.write_count += 1
        self._last_write_ts = time.time()


# ──────────────────────────────────────────────────────────────────
# CSV INPUT
# ──────────────────────────────────────────────────────────────────
def read_rule_names_from_csv(csv_path: str, logger: logging.Logger) -> List[str]:
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = {h.strip().lower(): h for h in reader.fieldnames or []}
        name_col = headers.get("name")

        if not name_col:
            raise ValueError("CSV must contain a 'Name' column.")

        names = []
        for row in reader:
            n = (row.get(name_col) or "").strip()
            if n.lower().startswith("[disabled]"):
                n = n[len("[disabled]"):].strip()
            if n:
                names.append(n)

    return list(dict.fromkeys(names))


# ──────────────────────────────────────────────────────────────────
# PANORAMA HELPERS
# ──────────────────────────────────────────────────────────────────
def discover_device_entry_name(pano: Panorama) -> str:
    resp = pano.xapi.get(xpath="/config/devices")
    for e in resp.findall(".//entry"):
        if e.get("name"):
            return e.get("name")
    raise RuntimeError("Unable to discover Panorama device entry name")


def dg_pre_xpath(device_entry: str, dg: str) -> str:
    return (
        f"/config/devices/entry[@name='{device_entry}']"
        f"/device-group/entry[@name='{dg}']"
        f"/pre-rulebase/security/rules"
    )


def dg_post_xpath(device_entry: str, dg: str) -> str:
    return (
        f"/config/devices/entry[@name='{device_entry}']"
        f"/device-group/entry[@name='{dg}']"
        f"/post-rulebase/security/rules"
    )


def build_rule_map(pano: Panorama, xpath: str) -> Dict[str, str]:
    resp = pano.xapi.get(xpath=xpath)
    rules = {}
    for e in resp.findall(".//entry"):
        if e.get("name"):
            rules[e.get("name")] = f"{xpath}/entry[@name='{e.get('name')}']"
    return rules


def is_rule_disabled(pano: Panorama, rule_xpath: str) -> bool:
    resp = pano.xapi.get(xpath=rule_xpath + "/disabled")
    elem = resp.find(".//disabled")
    return elem is not None and elem.text.strip().lower() == "yes"


def disable_rule(pano: Panorama, rule_xpath: str, limiter: WriteRateLimiter):
    limiter.before_write()
    pano.xapi.set(xpath=rule_xpath, element="<disabled>yes</disabled>")
    limiter.after_write()


# ──────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────
def main():
    logger, log_path = setup_logging()

    pano_ip = input("Panorama management IP/hostname: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    device_group = input("Target Device Group: ").strip()
    csv_path = input("CSV file path: ").strip()

    print("\n--- Rate Limiting Configuration ---")
    max_writes = int(input("Max writes before pause (0 = disable) [25]: ") or "25")
    pause_seconds = float(input("Pause duration in seconds [5]: ") or "5")
    min_spacing = float(input("Minimum seconds between writes [0.2]: ") or "0.2")

    logger.info(
        "User rate limits: max_writes=%s, pause_seconds=%s, min_spacing=%s",
        max_writes,
        pause_seconds,
        min_spacing,
    )

    limiter = WriteRateLimiter(
        logger=logger,
        max_writes_before_pause=max_writes,
        pause_seconds=pause_seconds,
        min_seconds_between_writes=min_spacing,
    )

    rule_names = read_rule_names_from_csv(csv_path, logger)
    logger.info("Loaded %d rule names from CSV", len(rule_names))

    pano = Panorama(hostname=pano_ip, api_username=username, api_password=password)
    device_entry = discover_device_entry_name(pano)

    pre_map = build_rule_map(pano, dg_pre_xpath(device_entry, device_group))
    post_map = build_rule_map(pano, dg_post_xpath(device_entry, device_group))

    results = []

    for name in rule_names:
        row = {"rule_name": name, "pre_status": "NOT_FOUND", "post_status": "NOT_FOUND"}

        if name in pre_map:
            if not is_rule_disabled(pano, pre_map[name]):
                disable_rule(pano, pre_map[name], limiter)
                row["pre_status"] = "DISABLED"
            else:
                row["pre_status"] = "ALREADY_DISABLED"

        if name in post_map:
            if not is_rule_disabled(pano, post_map[name]):
                disable_rule(pano, post_map[name], limiter)
                row["post_status"] = "DISABLED"
            else:
                row["post_status"] = "ALREADY_DISABLED"

        results.append(row)

    out_csv = f"panorama_disable_report_{device_group}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rule_name", "pre_status", "post_status"])
        writer.writeheader()
        writer.writerows(results)

    logger.info("CSV report written to: %s", out_csv)
    logger.info("Total write calls made: %d", limiter.write_count)
    logger.info("Done. Log file: %s", log_path)


if __name__ == "__main__":
    main()
