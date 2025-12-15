#!/usr/bin/env python3
"""
Disable PAN-OS *Panorama* Security rules by matching Policy Optimizer CSV column "Name",
querying BOTH Device Group Pre and Post rulebases, and generating a CSV report of results.

────────────────────────────────────────────────────────────────────
WHAT THIS SCRIPT DOES
────────────────────────────────────────────────────────────────────
Python side:
- Prompts for Panorama mgmt IP/hostname, username, password (getpass)
- Prompts for target Device Group and CSV path
- Extracts rule names from CSV "Name" column (Policy Optimizer export)
- De-duplicates rule names
- Logs progress to console and writes a timestamped log file
- Writes a timestamped CSV report with per-rule results for PRE and POST

Panorama side (candidate config only):
- Retrieves DG Pre-rulebase Security rules via XPath
- Retrieves DG Post-rulebase Security rules via XPath
- For each rule name:
    - If found: set <disabled>yes</disabled> (unless already disabled)
    - If not found: record NOT_FOUND
- Does NOT commit

CSV report includes:
- rule_name
- pre_status  (DISABLED / ALREADY_DISABLED / NOT_FOUND / ERROR)
- post_status (DISABLED / ALREADY_DISABLED / NOT_FOUND / ERROR)
- notes       (optional context)

────────────────────────────────────────────────────────────────────
ASSUMPTIONS
────────────────────────────────────────────────────────────────────
- Panorama only
- Security policy rules only
- CSV contains "Name" column
"""

import csv
import getpass
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Tuple

from panos.panorama import Panorama


# ──────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────
def setup_logging() -> Tuple[logging.Logger, str]:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.abspath(f"disable_panorama_rules_by_name_{ts}.log")

    logger = logging.getLogger("disable_panorama_by_name")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    logger.addHandler(sh)
    logger.addHandler(fh)

    logger.info("Logging initialized")
    logger.info("Log file location: %s", log_path)
    return logger, log_path


# ──────────────────────────────────────────────────────────────────
# CSV input parsing (Policy Optimizer)
# ──────────────────────────────────────────────────────────────────
def read_rule_names_from_csv(csv_path: str, logger: logging.Logger) -> List[str]:
    """
    Python side: extract rule names from CSV column "Name" and normalize.
    """
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV appears to have no header row.")

        headers = {h.strip().strip('"').strip("'").lower(): h for h in reader.fieldnames}
        name_col = headers.get("name") or headers.get("rule_name")
        if not name_col:
            raise ValueError(
                "CSV must contain a 'Name' column (Policy Optimizer export). "
                f"Found headers: {', '.join(reader.fieldnames)}"
            )

        names: List[str] = []
        for i, row in enumerate(reader, start=2):
            n = (row.get(name_col) or "").strip()
            if not n:
                logger.warning("Skipping CSV line %d: empty Name", i)
                continue

            # Normalize away possible prefix from some exports
            if n.lower().startswith("[disabled]"):
                n = n[len("[disabled]"):].strip()

            names.append(n)

    # De-dupe while preserving order
    deduped = list(dict.fromkeys(names))
    if len(deduped) != len(names):
        logger.info("De-duplicated rule names: %d → %d", len(names), len(deduped))
    return deduped


# ──────────────────────────────────────────────────────────────────
# Panorama XPath helpers
# ──────────────────────────────────────────────────────────────────
def discover_device_entry_name(pano: Panorama, logger: logging.Logger) -> str:
    """
    Panorama side: determine the /config/devices/entry[@name='...'] value.
    """
    resp = pano.xapi.get(xpath="/config/devices")
    for e in resp.findall(".//entry"):
        name = e.get("name")
        if name:
            logger.info("Discovered Panorama device entry name: %s", name)
            return name
    raise RuntimeError("Unable to discover Panorama device entry name under /config/devices")


def dg_pre_rules_xpath(device_entry: str, device_group: str) -> str:
    return (
        f"/config/devices/entry[@name='{device_entry}']"
        f"/device-group/entry[@name='{device_group}']"
        f"/pre-rulebase/security/rules"
    )


def dg_post_rules_xpath(device_entry: str, device_group: str) -> str:
    return (
        f"/config/devices/entry[@name='{device_entry}']"
        f"/device-group/entry[@name='{device_group}']"
        f"/post-rulebase/security/rules"
    )


def build_rule_map(pano: Panorama, rules_xpath: str, logger: logging.Logger, label: str) -> Dict[str, str]:
    """
    Panorama side: pull all rules under pre/post xpath and build name->entry_xpath map.
    """
    logger.info("Retrieving %s Security rules via XPath: %s", label, rules_xpath)
    resp = pano.xapi.get(xpath=rules_xpath)
    entries = resp.findall(".//entry")

    rule_map: Dict[str, str] = {}
    for e in entries:
        rname = e.get("name")
        if rname:
            rule_map[rname] = rules_xpath + f"/entry[@name='{rname}']"

    logger.info("Discovered %d %s Security rules in candidate config", len(rule_map), label)
    return rule_map


def is_rule_disabled(pano: Panorama, rule_xpath: str) -> bool:
    """
    Panorama side: read <disabled> value.
    """
    resp = pano.xapi.get(xpath=rule_xpath + "/disabled")
    elem = resp.find(".//disabled")
    return elem is not None and (elem.text or "").strip().lower() == "yes"


def disable_rule(pano: Panorama, rule_xpath: str) -> None:
    """
    Panorama side: set <disabled>yes</disabled> (candidate config, no commit).
    """
    pano.xapi.set(xpath=rule_xpath, element="<disabled>yes</disabled>")


# ──────────────────────────────────────────────────────────────────
# CSV report writer
# ──────────────────────────────────────────────────────────────────
def write_results_csv(
    rows: List[Dict[str, str]],
    device_group: str,
    logger: logging.Logger,
) -> str:
    """
    Python side: write a report CSV with per-rule PRE/POST status.
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.abspath(f"panorama_disable_report_{device_group}_{ts}.csv")

    fieldnames = ["rule_name", "pre_status", "post_status", "notes"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(
                {
                    "rule_name": r.get("rule_name", ""),
                    "pre_status": r.get("pre_status", ""),
                    "post_status": r.get("post_status", ""),
                    "notes": r.get("notes", ""),
                }
            )

    logger.info("CSV report written to: %s", out_path)
    return out_path


# ──────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────
def main() -> None:
    logger, log_path = setup_logging()
    logger.info("=== Panorama Security Rule Disabler (Name-based, Pre+Post + CSV Report) ===")

    pano_ip = input("Panorama management IP/hostname: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    device_group = input("Target Device Group name: ").strip()
    csv_path = input("CSV file path: ").strip()

    if not device_group:
        logger.error("Device Group name is required.")
        sys.exit(2)

    try:
        rule_names = read_rule_names_from_csv(csv_path, logger)
        logger.info("Loaded %d unique rule names from CSV", len(rule_names))
        if not rule_names:
            logger.warning("No rule names found. Exiting.")
            return

        # Connect to Panorama
        logger.info("Connecting to Panorama %s ...", pano_ip)
        pano = Panorama(hostname=pano_ip, api_username=username, api_password=password)

        # Discover base device entry and build pre/post maps
        device_entry = discover_device_entry_name(pano, logger)
        pre_xpath = dg_pre_rules_xpath(device_entry, device_group)
        post_xpath = dg_post_rules_xpath(device_entry, device_group)

        pre_map = build_rule_map(pano, pre_xpath, logger, label="PRE")
        post_map = build_rule_map(pano, post_xpath, logger, label="POST")

        # Totals
        totals = {
            "PRE_DISABLED": 0,
            "PRE_ALREADY_DISABLED": 0,
            "PRE_NOT_FOUND": 0,
            "POST_DISABLED": 0,
            "POST_ALREADY_DISABLED": 0,
            "POST_NOT_FOUND": 0,
            "ERROR": 0,
        }

        # Per-rule report rows
        report_rows: List[Dict[str, str]] = []

        for idx, name in enumerate(rule_names, start=1):
            logger.info("[%d/%d] Processing rule name: %s", idx, len(rule_names), name)

            row = {"rule_name": name, "pre_status": "NOT_FOUND", "post_status": "NOT_FOUND", "notes": ""}

            # ---- PRE processing ----
            pre_rule_xpath = pre_map.get(name)
            if pre_rule_xpath:
                try:
                    if is_rule_disabled(pano, pre_rule_xpath):
                        totals["PRE_ALREADY_DISABLED"] += 1
                        row["pre_status"] = "ALREADY_DISABLED"
                        logger.info("PRE already disabled: %s", name)
                    else:
                        disable_rule(pano, pre_rule_xpath)
                        totals["PRE_DISABLED"] += 1
                        row["pre_status"] = "DISABLED"
                        logger.info("PRE disabled: %s", name)
                except Exception as e:
                    totals["ERROR"] += 1
                    row["pre_status"] = "ERROR"
                    row["notes"] = f"PRE error: {e}"
                    logger.exception("ERROR disabling PRE rule '%s': %s", name, e)
            else:
                totals["PRE_NOT_FOUND"] += 1
                row["pre_status"] = "NOT_FOUND"
                logger.info("PRE not found: %s", name)

            # ---- POST processing ----
            post_rule_xpath = post_map.get(name)
            if post_rule_xpath:
                try:
                    if is_rule_disabled(pano, post_rule_xpath):
                        totals["POST_ALREADY_DISABLED"] += 1
                        row["post_status"] = "ALREADY_DISABLED"
                        logger.info("POST already disabled: %s", name)
                    else:
                        disable_rule(pano, post_rule_xpath)
                        totals["POST_DISABLED"] += 1
                        row["post_status"] = "DISABLED"
                        logger.info("POST disabled: %s", name)
                except Exception as e:
                    totals["ERROR"] += 1
                    row["post_status"] = "ERROR"
                    # append notes if PRE already has notes
                    if row["notes"]:
                        row["notes"] += f" | POST error: {e}"
                    else:
                        row["notes"] = f"POST error: {e}"
                    logger.exception("ERROR disabling POST rule '%s': %s", name, e)
            else:
                totals["POST_NOT_FOUND"] += 1
                row["post_status"] = "NOT_FOUND"
                logger.info("POST not found: %s", name)

            report_rows.append(row)

        # Write CSV report
        report_path = write_results_csv(report_rows, device_group, logger)

        # Summary
        logger.info("=== Summary (Device Group: %s) ===", device_group)
        logger.info("PRE  Disabled:         %d", totals["PRE_DISABLED"])
        logger.info("PRE  Already disabled: %d", totals["PRE_ALREADY_DISABLED"])
        logger.info("PRE  Not found:        %d", totals["PRE_NOT_FOUND"])
        logger.info("POST Disabled:         %d", totals["POST_DISABLED"])
        logger.info("POST Already disabled: %d", totals["POST_ALREADY_DISABLED"])
        logger.info("POST Not found:        %d", totals["POST_NOT_FOUND"])
        logger.info("Errors:               %d", totals["ERROR"])
        logger.info("CSV report: %s", report_path)
        logger.info("Log file:  %s", log_path)

    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        logger.error("Exiting. Log file: %s", log_path)
        sys.exit(2)


if __name__ == "__main__":
    main()
