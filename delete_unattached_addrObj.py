"""
OVERVIEW:

This cleanup tool finds address objects and groups that are not attached to any Pre or Post rulebase policy on a Palo Alto Panorama
server. The tool checks the Shared device group and a target device group specified by the user. First, it generates a CSV report of the 
found objects. Then it waits for user confirmation on whether to proceed with the deletion process. If the tool is prompted to proceed, 
it will delete the objects from the candidate configuration. After review, commits to the running configuration can be made from the GUI or CLI.
Once the script is done, it will generate an log file for any possible errors.

FEATURES:

Python side:
- Prompts for Panorama mgmt IP/hostname, username, password (getpass)
- Prompts for user-driven rate limiting (WRITE calls only)
- Pulls Address Objects + Address Groups from candidate config
- Pulls the vsys rulebase subtree from candidate config and collects <member> references
- Determines which objects/groups are referenced by policies, including nested groups (multi-level)
- Generates a CSV report of unattached objects/groups (includes description + group members)
- Waits for user confirmation ("DELETE") before deleting anything
- Deletes nested groups safely (outermost → innermost) with retries
- Deletes objects after groups
- Generates an AFTER deletion CSV report listing anything that failed to delete and why
- Logs progress to console and to a timestamped log file

Panorama side:
- Uses pan-os-python SDK only (Firewall + xapi)
- Reads config via XPath GET (candidate config)
- Deletes config via XPath DELETE (candidate config)
- NO commit is performed

ASSUMPTIONS / SCOPE:

- Panorama only
- No commit performed
- Deletions occur in candidate config only

MINUMUM SOFTWARE:
- Python 3.9.5
- PAN-OS SDK 1.12.0
- PAN-OS Software Version: 11.X.X

"""

import csv
import getpass
import logging
import os
import re
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from panos.panorama import Panorama


# ──────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────
def setup_logging() -> Tuple[logging.Logger, str]:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.abspath(f"pano_unattached_addr_cleanup_{ts}.log")

    logger = logging.getLogger("pano_unattached_addr_cleanup")
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
    logger.info("Log file: %s", log_path)
    return logger, log_path


# ──────────────────────────────────────────────────────────────────
# RATE LIMITER (WRITE CALLS ONLY)
# ──────────────────────────────────────────────────────────────────
class WriteRateLimiter:
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

    def before_write(self) -> None:
        if self.min_seconds_between_writes and self._last_write_ts is not None:
            elapsed = time.time() - self._last_write_ts
            if elapsed < self.min_seconds_between_writes:
                time.sleep(self.min_seconds_between_writes - elapsed)

        if self.max_writes_before_pause and self.write_count > 0:
            if self.write_count % self.max_writes_before_pause == 0:
                self.logger.info(
                    "Rate limit: %d writes reached, pausing for %s seconds...",
                    self.write_count,
                    self.pause_seconds,
                )
                time.sleep(self.pause_seconds)

    def after_write(self) -> None:
        self.write_count += 1
        self._last_write_ts = time.time()


def prompt_int(prompt: str, default: int) -> int:
    raw = input(f"{prompt} [{default}]: ").strip()
    return default if raw == "" else int(raw)


def prompt_float(prompt: str, default: float) -> float:
    raw = input(f"{prompt} [{default}]: ").strip()
    return default if raw == "" else float(raw)


# ──────────────────────────────────────────────────────────────────
# XPATH HELPERS
# ──────────────────────────────────────────────────────────────────
def discover_device_entry_name(pano: Panorama, logger: logging.Logger) -> str:
    resp = pano.xapi.get(xpath="/config/devices")
    for e in resp.findall(".//entry"):
        name = e.get("name")
        if name:
            logger.info("Discovered Panorama device entry name: %s", name)
            return name
    raise RuntimeError("Unable to discover Panorama device entry name under /config/devices")


def dg_root_xpath(device_entry: str) -> str:
    return f"/config/devices/entry[@name='{device_entry}']/device-group"


def list_device_groups(pano: Panorama, device_entry: str, logger: logging.Logger) -> List[str]:
    """
    Panorama side: list all device-group names under /device-group
    """
    xpath = dg_root_xpath(device_entry)
    logger.info("Discovering Device Groups via XPath: %s", xpath)
    resp = pano.xapi.get(xpath=xpath)
    dgs = sorted({e.get("name") for e in resp.findall(".//entry") if e.get("name")})
    logger.info("Found %d Device Groups.", len(dgs))
    return dgs


def dg_address_xpath(device_entry: str, dg: str) -> str:
    return f"/config/devices/entry[@name='{device_entry}']/device-group/entry[@name='{dg}']/address"


def dg_address_group_xpath(device_entry: str, dg: str) -> str:
    return f"/config/devices/entry[@name='{device_entry}']/device-group/entry[@name='{dg}']/address-group"


def dg_pre_rulebase_xpath(device_entry: str, dg: str) -> str:
    return f"/config/devices/entry[@name='{device_entry}']/device-group/entry[@name='{dg}']/pre-rulebase"


def dg_post_rulebase_xpath(device_entry: str, dg: str) -> str:
    return f"/config/devices/entry[@name='{device_entry}']/device-group/entry[@name='{dg}']/post-rulebase"


def shared_address_xpath() -> str:
    return "/config/shared/address"


def shared_address_group_xpath() -> str:
    return "/config/shared/address-group"


def shared_pre_rulebase_xpath() -> str:
    return "/config/shared/pre-rulebase"


def shared_post_rulebase_xpath() -> str:
    return "/config/shared/post-rulebase"


# ──────────────────────────────────────────────────────────────────
# OBJECT/GROUP LOADERS
# ──────────────────────────────────────────────────────────────────
def _get_description(entry_elem) -> str:
    d = entry_elem.find("./description")
    if d is not None and d.text:
        return d.text.strip()
    return ""


def load_address_objects(
    pano: Panorama, xpath: str, logger: logging.Logger, label: str
) -> Tuple[Set[str], Dict[str, str]]:
    logger.info("Pulling %s address objects via XPath: %s", label, xpath)
    resp = pano.xapi.get(xpath=xpath)

    names: Set[str] = set()
    desc_map: Dict[str, str] = {}

    for e in resp.findall(".//entry"):
        n = e.get("name")
        if not n:
            continue
        names.add(n)
        desc_map[n] = _get_description(e)

    logger.info("Found %d %s address objects.", len(names), label)
    return names, desc_map


def load_address_groups(
    pano: Panorama, xpath: str, logger: logging.Logger, label: str
) -> Tuple[Set[str], Dict[str, List[str]], Dict[str, str]]:
    logger.info("Pulling %s address groups via XPath: %s", label, xpath)
    resp = pano.xapi.get(xpath=xpath)

    group_names: Set[str] = set()
    members_map: Dict[str, List[str]] = {}
    desc_map: Dict[str, str] = {}

    for e in resp.findall(".//entry"):
        gname = e.get("name")
        if not gname:
            continue
        group_names.add(gname)
        desc_map[gname] = _get_description(e)
        members = [m.text.strip() for m in e.findall(".//member") if m.text and m.text.strip()]
        members_map[gname] = members

    logger.info("Found %d %s address groups.", len(group_names), label)
    return group_names, members_map, desc_map


# ──────────────────────────────────────────────────────────────────
# POLICY MEMBER COLLECTION (ALL DGS + SHARED)
# ──────────────────────────────────────────────────────────────────
def collect_members_under_xpath(
    pano: Panorama, xpath: str, logger: logging.Logger, label: str
) -> Set[str]:
    """
    Pull an entire subtree and collect all <member> values.
    If the subtree does not exist, returns empty set.
    """
    try:
        logger.info("Pulling %s subtree via XPath: %s", label, xpath)
        resp = pano.xapi.get(xpath=xpath)
    except Exception as e:
        logger.warning("Could not read %s subtree (skipping): %s", label, e)
        return set()

    members: Set[str] = set()
    for m in resp.findall(".//member"):
        if m.text and m.text.strip():
            members.add(m.text.strip())

    logger.info("Collected %d unique <member> values from %s.", len(members), label)
    return members


def collect_all_dg_policy_members(
    pano: Panorama,
    device_entry: str,
    dg_names: List[str],
    logger: logging.Logger,
) -> Set[str]:
    """
    Conservative: collect <member> values from PRE+POST rulebase of ALL device groups.
    """
    all_members: Set[str] = set()
    for dg in dg_names:
        pre = collect_members_under_xpath(
            pano, dg_pre_rulebase_xpath(device_entry, dg), logger, label=f"DG:{dg} PRE"
        )
        post = collect_members_under_xpath(
            pano, dg_post_rulebase_xpath(device_entry, dg), logger, label=f"DG:{dg} POST"
        )
        all_members |= pre | post

    logger.info("Total unique <member> values across ALL DG PRE+POST: %d", len(all_members))
    return all_members


def collect_shared_policy_members(pano: Panorama, logger: logging.Logger) -> Set[str]:
    """
    Shared pre/post rulebase may or may not exist depending on your config.
    """
    pre = collect_members_under_xpath(pano, shared_pre_rulebase_xpath(), logger, label="SHARED PRE")
    post = collect_members_under_xpath(pano, shared_post_rulebase_xpath(), logger, label="SHARED POST")
    return pre | post


# ──────────────────────────────────────────────────────────────────
# USED/UNUSED CALCULATION
# ──────────────────────────────────────────────────────────────────
def compute_used_sets(
    all_addresses: Set[str],
    all_groups: Set[str],
    group_members: Dict[str, List[str]],
    policy_members: Set[str],
    logger: logging.Logger,
    label: str,
) -> Tuple[Set[str], Set[str]]:
    used_addresses: Set[str] = set(m for m in policy_members if m in all_addresses)
    used_groups: Set[str] = set(m for m in policy_members if m in all_groups)

    logger.info("[%s] Directly referenced: %d addresses, %d groups.", label, len(used_addresses), len(used_groups))

    stack = list(used_groups)
    visited: Set[str] = set()

    while stack:
        g = stack.pop()
        if g in visited:
            continue
        visited.add(g)
        for member in group_members.get(g, []):
            if member in all_addresses:
                used_addresses.add(member)
            elif member in all_groups:
                if member not in used_groups:
                    used_groups.add(member)
                stack.append(member)

    logger.info(
        "[%s] After recursive expansion: %d used addresses, %d used groups.",
        label, len(used_addresses), len(used_groups)
    )
    return used_addresses, used_groups


# ──────────────────────────────────────────────────────────────────
# REPORTING (PRE-DELETE)
# ──────────────────────────────────────────────────────────────────
def write_unattached_report_csv(
    pano_ip: str,
    target_dg: str,
    dg_unattached_addresses: Set[str],
    dg_unattached_groups: Set[str],
    dg_group_members: Dict[str, List[str]],
    dg_addr_desc: Dict[str, str],
    dg_group_desc: Dict[str, str],
    shared_unattached_addresses: Set[str],
    shared_unattached_groups: Set[str],
    shared_group_members: Dict[str, List[str]],
    shared_addr_desc: Dict[str, str],
    shared_group_desc: Dict[str, str],
    logger: logging.Logger,
) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.abspath(f"pano_{pano_ip}_{target_dg}_unattached_objects_{ts}.csv")

    fieldnames = ["scope", "object_type", "name", "description", "members", "notes"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        # DG groups
        for g in sorted(dg_unattached_groups):
            w.writerow(
                {
                    "scope": f"device-group:{target_dg}",
                    "object_type": "address-group",
                    "name": g,
                    "description": dg_group_desc.get(g, ""),
                    "members": ";".join(dg_group_members.get(g, [])),
                    "notes": "Not referenced in ANY DG pre/post or shared pre/post (directly or via used groups)",
                }
            )

        # DG addresses
        for a in sorted(dg_unattached_addresses):
            w.writerow(
                {
                    "scope": f"device-group:{target_dg}",
                    "object_type": "address",
                    "name": a,
                    "description": dg_addr_desc.get(a, ""),
                    "members": "",
                    "notes": "Not referenced in ANY DG pre/post or shared pre/post (directly or via used groups)",
                }
            )

        # Shared groups
        for g in sorted(shared_unattached_groups):
            w.writerow(
                {
                    "scope": "shared",
                    "object_type": "address-group",
                    "name": g,
                    "description": shared_group_desc.get(g, ""),
                    "members": ";".join(shared_group_members.get(g, [])),
                    "notes": "Not referenced in ANY DG pre/post or shared pre/post (directly or via used groups)",
                }
            )

        # Shared addresses
        for a in sorted(shared_unattached_addresses):
            w.writerow(
                {
                    "scope": "shared",
                    "object_type": "address",
                    "name": a,
                    "description": shared_addr_desc.get(a, ""),
                    "members": "",
                    "notes": "Not referenced in ANY DG pre/post or shared pre/post (directly or via used groups)",
                }
            )

    logger.info("Unattached objects report written to: %s", out_path)
    return out_path


# ──────────────────────────────────────────────────────────────────
# NESTED GROUP SAFE DELETE ORDER
# ──────────────────────────────────────────────────────────────────
def _extract_nested_group_edges(groups: Set[str], members: Dict[str, List[str]]) -> Dict[str, Set[str]]:
    edges: Dict[str, Set[str]] = {g: set() for g in groups}
    for parent in groups:
        for m in members.get(parent, []):
            if m in groups:
                edges[parent].add(m)
    return edges


def compute_group_deletion_order(groups: Set[str], members: Dict[str, List[str]], logger: logging.Logger) -> List[str]:
    """
    If parent contains child, parent must be deleted BEFORE child.
    """
    edges = _extract_nested_group_edges(groups, members)
    in_deg: Dict[str, int] = {g: 0 for g in groups}
    for p, children in edges.items():
        for c in children:
            in_deg[c] += 1

    queue = sorted([g for g, d in in_deg.items() if d == 0])
    order: List[str] = []

    while queue:
        g = queue.pop(0)
        order.append(g)
        for child in edges.get(g, set()):
            in_deg[child] -= 1
            if in_deg[child] == 0:
                queue.append(child)
                queue.sort()

    remaining = [g for g in groups if g not in order]
    if remaining:
        logger.warning(
            "Unresolved nesting for %d group(s) (possible cycle). They will be attempted last.",
            len(remaining),
        )
        order.extend(sorted(remaining))

    return order


# ──────────────────────────────────────────────────────────────────
# AFTER-DELETION FAILURE REPORT
# ──────────────────────────────────────────────────────────────────
def extract_reference_path(err: Exception) -> str:
    msg = str(err).replace("\r\n", "\n").replace("\r", "\n")
    m = re.search(r"references from:\s*(.+)$", msg, flags=re.IGNORECASE | re.DOTALL)
    if m:
        ref = m.group(1).strip()
        return " | ".join([line.strip() for line in ref.split("\n") if line.strip()])
    return ""


def write_after_deletion_report_csv(
    pano_ip: str, target_dg: str, failures: List[Dict[str, str]], logger: logging.Logger
) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.abspath(f"pano_{pano_ip}_{target_dg}_post_delete_failures_{ts}.csv")

    fieldnames = ["scope", "object_type", "name", "attempted_xpath", "error", "reference_path"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in failures:
            w.writerow({k: row.get(k, "") for k in fieldnames})

    logger.info("After-deletion failure report written to: %s", out_path)
    return out_path


# ──────────────────────────────────────────────────────────────────
# DELETE HELPERS
# ──────────────────────────────────────────────────────────────────
def delete_xpath(pano: Panorama, xpath: str, limiter: WriteRateLimiter) -> None:
    limiter.before_write()
    pano.xapi.delete(xpath=xpath)
    limiter.after_write()


def delete_scope_objects(
    pano: Panorama,
    scope_label: str,
    group_base_xpath: str,
    addr_base_xpath: str,
    groups_to_delete: Set[str],
    addrs_to_delete: Set[str],
    group_members: Dict[str, List[str]],
    limiter: WriteRateLimiter,
    logger: logging.Logger,
    failures: List[Dict[str, str]],
) -> Dict[str, int]:
    """
    Deletes groups (outer -> inner with retries) then addresses.
    Records failures for after-report.
    """
    totals = {"GROUP_DELETED": 0, "ADDR_DELETED": 0, "DELETE_ERRORS": 0}

    # Groups first, nested-safe
    order = compute_group_deletion_order(groups_to_delete, group_members, logger)
    pending = list(order)
    max_passes = max(2, len(pending))

    logger.info("[%s] Deleting %d groups with up to %d passes...", scope_label, len(groups_to_delete), max_passes)

    for pass_num in range(1, max_passes + 1):
        if not pending:
            break
        next_pending: List[str] = []
        progress = 0

        logger.info("[%s] Group delete pass %d: %d pending", scope_label, pass_num, len(pending))
        for g in pending:
            xpath = f"{group_base_xpath}/entry[@name='{g}']"
            try:
                logger.info("[%s] DELETE group: %s", scope_label, g)
                delete_xpath(pano, xpath, limiter)
                totals["GROUP_DELETED"] += 1
                progress += 1
            except Exception as e:
                totals["DELETE_ERRORS"] += 1
                next_pending.append(g)
                failures.append(
                    {
                        "scope": scope_label,
                        "object_type": "address-group",
                        "name": g,
                        "attempted_xpath": xpath,
                        "error": str(e),
                        "reference_path": extract_reference_path(e),
                    }
                )
                logger.warning("[%s] Could not delete group '%s' (will retry): %s", scope_label, g, e)

        if progress == 0:
            logger.warning("[%s] No progress in pass %d. Remaining groups likely have external references.", scope_label, pass_num)
            pending = next_pending
            break

        pending = next_pending

    # Remove stale group failures if group deleted in later passes
    deleted_groups = set(order) - set(pending)
    if deleted_groups:
        failures[:] = [
            f for f in failures
            if not (f.get("scope") == scope_label and f.get("object_type") == "address-group" and f.get("name") in deleted_groups)
        ]

    # Addresses after groups
    logger.info("[%s] Deleting %d addresses...", scope_label, len(addrs_to_delete))
    for a in sorted(addrs_to_delete):
        xpath = f"{addr_base_xpath}/entry[@name='{a}']"
        try:
            logger.info("[%s] DELETE address: %s", scope_label, a)
            delete_xpath(pano, xpath, limiter)
            totals["ADDR_DELETED"] += 1
        except Exception as e:
            totals["DELETE_ERRORS"] += 1
            failures.append(
                {
                    "scope": scope_label,
                    "object_type": "address",
                    "name": a,
                    "attempted_xpath": xpath,
                    "error": str(e),
                    "reference_path": extract_reference_path(e),
                }
            )
            logger.exception("[%s] Failed to delete address '%s': %s", scope_label, a, e)

    return totals


# ──────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────
def main() -> None:
    logger, log_path = setup_logging()
    logger.info("=== Panorama Unattached Address/Group Finder + Optional Deleter (DG + Shared, All-DG policy scan) ===")

    pano_ip = input("Panorama management IP/hostname: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    target_dg = input("Target Device Group name: ").strip()

    if not target_dg:
        logger.error("Target Device Group is required.")
        sys.exit(2)

    print("\n--- Rate Limiting Configuration (WRITE calls only: deletes) ---")
    max_writes = prompt_int("Max writes before pause (0 = disable pause-by-count)", 25)
    pause_seconds = prompt_float("Pause duration in seconds", 5.0)
    min_spacing = prompt_float("Minimum seconds between writes (0 = no spacing)", 0.2)

    logger.info("User rate limits: max_writes=%s, pause_seconds=%s, min_spacing=%s", max_writes, pause_seconds, min_spacing)

    limiter = WriteRateLimiter(
        logger=logger,
        max_writes_before_pause=max_writes,
        pause_seconds=pause_seconds,
        min_seconds_between_writes=min_spacing,
    )

    pano_ip_for_reports = pano_ip.replace(":", "_")

    try:
        logger.info("Connecting to Panorama %s ...", pano_ip)
        pano = Panorama(hostname=pano_ip, api_username=username, api_password=password)

        device_entry = discover_device_entry_name(pano, logger)
        dg_names = list_device_groups(pano, device_entry, logger)

        if target_dg not in dg_names:
            logger.warning("Target DG '%s' not found in DG list. Proceeding anyway (might be permissions).", target_dg)

        # 1) Load TARGET DG objects/groups
        dg_addr_xpath = dg_address_xpath(device_entry, target_dg)
        dg_ag_xpath = dg_address_group_xpath(device_entry, target_dg)

        dg_addrs, dg_addr_desc = load_address_objects(pano, dg_addr_xpath, logger, label=f"DG:{target_dg}")
        dg_groups, dg_group_members, dg_group_desc = load_address_groups(pano, dg_ag_xpath, logger, label=f"DG:{target_dg}")

        # 2) Load SHARED objects/groups
        shared_addrs, shared_addr_desc = load_address_objects(pano, shared_address_xpath(), logger, label="SHARED")
        shared_groups, shared_group_members, shared_group_desc = load_address_groups(pano, shared_address_group_xpath(), logger, label="SHARED")

        # 3) Collect policy references from ALL DG pre/post
        all_dg_policy_members = collect_all_dg_policy_members(pano, device_entry, dg_names, logger)

        # 4) Collect shared policy refs (if present)
        shared_policy_members = collect_shared_policy_members(pano, logger)

        # 5) Compute used/unattached for TARGET DG scope
        # Conservative: treat DG objects as "used" if referenced in ANY DG policy or shared policy
        policy_members_for_dg = all_dg_policy_members | shared_policy_members

        dg_used_addrs, dg_used_groups = compute_used_sets(
            all_addresses=dg_addrs,
            all_groups=dg_groups,
            group_members=dg_group_members,
            policy_members=policy_members_for_dg,
            logger=logger,
            label=f"DG:{target_dg}",
        )
        dg_unattached_addrs = dg_addrs - dg_used_addrs
        dg_unattached_groups = dg_groups - dg_used_groups

        # 6) Compute used/unattached for SHARED scope (checked against ALL DG + shared policies)
        policy_members_for_shared = all_dg_policy_members | shared_policy_members

        shared_used_addrs, shared_used_groups = compute_used_sets(
            all_addresses=shared_addrs,
            all_groups=shared_groups,
            group_members=shared_group_members,
            policy_members=policy_members_for_shared,
            logger=logger,
            label="SHARED",
        )
        shared_unattached_addrs = shared_addrs - shared_used_addrs
        shared_unattached_groups = shared_groups - shared_used_groups

        logger.info("=== Unattached Totals ===")
        logger.info("DG:%s unattached groups: %d", target_dg, len(dg_unattached_groups))
        logger.info("DG:%s unattached addrs : %d", target_dg, len(dg_unattached_addrs))
        logger.info("SHARED unattached groups: %d", len(shared_unattached_groups))
        logger.info("SHARED unattached addrs : %d", len(shared_unattached_addrs))

        # 7) Write PRE-delete report (includes BOTH scopes)
        pre_report = write_unattached_report_csv(
            pano_ip=pano_ip_for_reports,
            target_dg=target_dg,
            dg_unattached_addresses=dg_unattached_addrs,
            dg_unattached_groups=dg_unattached_groups,
            dg_group_members=dg_group_members,
            dg_addr_desc=dg_addr_desc,
            dg_group_desc=dg_group_desc,
            shared_unattached_addresses=shared_unattached_addrs,
            shared_unattached_groups=shared_unattached_groups,
            shared_group_members=shared_group_members,
            shared_addr_desc=shared_addr_desc,
            shared_group_desc=shared_group_desc,
            logger=logger,
        )

        if not (dg_unattached_addrs or dg_unattached_groups or shared_unattached_addrs or shared_unattached_groups):
            logger.info("No unattached objects/groups found. Nothing to delete.")
            logger.info("Pre-delete report: %s", pre_report)
            logger.info("Log: %s", log_path)
            return

        print("\n============================================================")
        print("PRE-DELETE REPORT GENERATED (includes DG + SHARED)")
        print(f"  Report: {pre_report}")
        print("============================================================")
        print("Next step: delete the unattached objects/groups from CANDIDATE config.")
        print("This script WILL NOT commit.")
        print("============================================================\n")

        confirm = input("Type 'DELETE' to proceed with deletion, or anything else to exit: ").strip()
        if confirm != "DELETE":
            logger.info("User did not confirm deletion. Exiting without changes.")
            logger.info("Pre-delete report: %s", pre_report)
            logger.info("Log: %s", log_path)
            return

        failures: List[Dict[str, str]] = []

        # 8) Delete TARGET DG scope
        dg_totals = delete_scope_objects(
            pano=pano,
            scope_label=f"device-group:{target_dg}",
            group_base_xpath=dg_ag_xpath,
            addr_base_xpath=dg_addr_xpath,
            groups_to_delete=dg_unattached_groups,
            addrs_to_delete=dg_unattached_addrs,
            group_members=dg_group_members,
            limiter=limiter,
            logger=logger,
            failures=failures,
        )

        # 9) Delete SHARED scope
        shared_totals = delete_scope_objects(
            pano=pano,
            scope_label="shared",
            group_base_xpath=shared_address_group_xpath(),
            addr_base_xpath=shared_address_xpath(),
            groups_to_delete=shared_unattached_groups,
            addrs_to_delete=shared_unattached_addrs,
            group_members=shared_group_members,
            limiter=limiter,
            logger=logger,
            failures=failures,
        )

        # 10) After-delete failure report
        after_report = write_after_deletion_report_csv(
            pano_ip=pano_ip_for_reports,
            target_dg=target_dg,
            failures=failures,
            logger=logger,
        )

        # Summary
        logger.info("=== Deletion Summary (candidate config only; no commit performed) ===")
        logger.info("DG:%s groups deleted: %d", target_dg, dg_totals["GROUP_DELETED"])
        logger.info("DG:%s addrs deleted : %d", target_dg, dg_totals["ADDR_DELETED"])
        logger.info("SHARED groups deleted: %d", shared_totals["GROUP_DELETED"])
        logger.info("SHARED addrs deleted : %d", shared_totals["ADDR_DELETED"])
        logger.info("Total delete errors: %d", dg_totals["DELETE_ERRORS"] + shared_totals["DELETE_ERRORS"])
        logger.info("Write calls made: %d", limiter.write_count)
        logger.info("Pre-delete report : %s", pre_report)
        logger.info("After-delete report: %s", after_report)
        logger.info("Log: %s", log_path)

    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        logger.error("Exiting. Log file: %s", log_path)
        sys.exit(2)


if __name__ == "__main__":
    main()
