#!/usr/bin/env python3
"""
Panorama (strict, no-commit) tagging script with logging, rate limiting, and CSV audit logging.

What it does:
  - Expands nested STATIC Address Groups recursively (cycle-protected).
  - Tags all Address Objects (Shared + DG) that belong to the target group.
  - Skips dynamic groups, missing members, or objects that already have the tag.
  - Throttles API writes using rate limiting and batch pauses.
  - Logs detailed actions (INFO/WARNING/ERROR) to console and log file.
  - Writes CSV audit file with per-object outcomes.

Requirements:
  pip install pan-os-python pandas
"""

import sys
import time
import getpass
import logging
import pandas as pd
from datetime import datetime
from typing import Optional, Set, Dict, Tuple, Union, List

# Panorama SDK
from panos.panorama import Panorama, DeviceGroup
from panos.objects import AddressObject, AddressGroup, Tag
from panos.errors import PanDeviceError

# -------------------------
# 🔧 User input (strict)
# -------------------------
USERNAME = input("Panorama username: ").strip()
if not USERNAME:
    sys.exit("❌ ERROR: Username cannot be blank.")

PASSWORD = getpass.getpass("Panorama password: ")
if not PASSWORD:
    sys.exit("❌ ERROR: Password cannot be blank.")

PANORAMA_IP = input("Panorama management IP / FQDN: ").strip()
if not PANORAMA_IP:
    sys.exit("❌ ERROR: Panorama management IP cannot be blank.")

TARGET_SCOPE = input("Target scope (Device Group name OR 'shared'): ").strip()
if not TARGET_SCOPE:
    sys.exit("❌ ERROR: Target scope cannot be blank.")

TARGET_STATIC_GROUP = input("Target STATIC Address Group name (must exist in the chosen scope): ").strip()
if not TARGET_STATIC_GROUP:
    sys.exit("❌ ERROR: Address Group name cannot be blank.")

DYNAMIC_MATCH_TAG = input("Tag to apply to Address Objects: ").strip()
if not DYNAMIC_MATCH_TAG:
    sys.exit("❌ ERROR: Tag name cannot be blank.")

# Rate limiting inputs
try:
    MAX_RPS = float(input("Max write operations per second (e.g., 2): ").strip())
    if MAX_RPS <= 0:
        raise ValueError
except ValueError:
    sys.exit("❌ ERROR: Max write operations per second must be a positive number.")

try:
    BATCH_SIZE = int(input("Batch size before pausing (e.g., 20): ").strip())
    if BATCH_SIZE <= 0:
        raise ValueError
except ValueError:
    sys.exit("❌ ERROR: Batch size must be a positive integer.")

try:
    BATCH_PAUSE_SEC = float(input("Batch pause duration in seconds (e.g., 5): ").strip())
    if BATCH_PAUSE_SEC < 0:
        raise ValueError
except ValueError:
    sys.exit("❌ ERROR: Batch pause duration must be non-negative.")

LOG_FILE = input("Optional log file path (press Enter to skip): ").strip()

# -------------------------
# 🧾 Logging Configuration
# -------------------------
log_level = logging.INFO
logger = logging.getLogger("PanoramaTagger")
logger.setLevel(log_level)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(log_level)
console_formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%H:%M:%S")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Optional file handler
if LOG_FILE:
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    logger.info(f"Logging to file: {LOG_FILE}")

# -------------------------
# ⏱️ Rate Limiter
# -------------------------
class RateLimiter:
    """Simple wall-clock rate limiter with batch pauses."""
    def __init__(self, rps: float, batch_size: int, batch_pause: float):
        self.min_interval = 1.0 / rps
        self.last_ts = 0.0
        self.batch_size = batch_size
        self.batch_pause = batch_pause
        self.counter = 0

    def wait(self):
        now = time.monotonic()
        delta = now - self.last_ts
        if self.last_ts != 0.0 and delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self.last_ts = time.monotonic()
        self.counter += 1
        if self.counter >= self.batch_size:
            logger.info(f"⏸️  Batch limit reached ({self.batch_size} ops). Pausing for {self.batch_pause}s.")
            if self.batch_pause > 0:
                time.sleep(self.batch_pause)
            self.counter = 0


limiter = RateLimiter(MAX_RPS, BATCH_SIZE, BATCH_PAUSE_SEC)

# -------------------------
# Helper Functions
# -------------------------
def connect_panorama() -> Panorama:
    """Connect to Panorama."""
    try:
        logger.info(f"Connecting to Panorama at {PANORAMA_IP} ...")
        pano = Panorama(hostname=PANORAMA_IP, api_username=USERNAME, api_password=PASSWORD)
        return pano
    except Exception as e:
        logger.error(f"Failed to connect to Panorama: {e}")
        sys.exit(1)


def get_scope_container(pano: Panorama, scope_name: str) -> Union[Panorama, DeviceGroup]:
    """Return container for the chosen scope."""
    if scope_name.lower() == "shared":
        logger.info("Operating in SHARED scope.")
        return pano

    dgs = DeviceGroup.refreshall(pano, add=False) or []
    for dg in dgs:
        if dg.name == scope_name:
            container = DeviceGroup(name=dg.name)
            pano.add(container)
            logger.info(f"Operating in Device Group: {scope_name}")
            return container
    sys.exit(f"❌ ERROR: Device Group '{scope_name}' not found on Panorama.")


def load_maps(container: Union[Panorama, DeviceGroup]) -> Tuple[Dict[str, AddressObject], Dict[str, AddressGroup]]:
    """Load all Address Objects & Groups for the scope."""
    logger.debug(f"Loading address objects/groups from scope: {container}")
    objs = AddressObject.refreshall(container, add=False) or []
    groups = AddressGroup.refreshall(container, add=False) or []
    return ({o.name: o for o in objs}, {g.name: g for g in groups})


def find_static_group(container: Union[Panorama, DeviceGroup], name: str) -> Optional[AddressGroup]:
    groups = AddressGroup.refreshall(container, add=False) or []
    for g in groups:
        if g.name == name:
            return g
    return None


# ---------- Resolution ----------
def resolve_member_to_object_pairs(
    member_name: str,
    obj_map_local: Dict[str, AddressObject],
    grp_map_local: Dict[str, AddressGroup],
    obj_map_shared: Dict[str, AddressObject],
    grp_map_shared: Dict[str, AddressGroup],
    member_skips: List[Dict[str, str]],
    seen: Optional[Set[Tuple[str, str]]] = None,
) -> Set[Tuple[str, str]]:
    """Resolve a member into (object_name, scope) pairs."""
    if seen is None:
        seen = set()

    identities = []
    if member_name in obj_map_local or member_name in grp_map_local:
        identities.append((member_name, 'local'))
    if member_name in obj_map_shared or member_name in grp_map_shared:
        identities.append((member_name, 'shared'))

    if not identities:
        logger.warning(f"Member '{member_name}' not found in local/shared.")
        member_skips.append({"member": member_name, "scope": "unknown", "reason": "not found"})
        return set()

    results: Set[Tuple[str, str]] = set()
    for name, scope in identities:
        identity = (name, scope)
        if identity in seen:
            logger.warning(f"Cyclic reference detected on '{name}' ({scope}), skipping.")
            member_skips.append({"member": name, "scope": scope, "reason": "cyclic reference"})
            continue
        seen.add(identity)

        if scope == 'local' and name in obj_map_local:
            results.add((name, 'local'))
            continue
        if scope == 'shared' and name in obj_map_shared:
            results.add((name, 'shared'))
            continue

        group = grp_map_local.get(name) if scope == 'local' else grp_map_shared.get(name)
        if not group:
            continue
        if group.static_value:
            for child in group.static_value:
                results |= resolve_member_to_object_pairs(
                    child, obj_map_local, grp_map_local, obj_map_shared, grp_map_shared, member_skips, seen=seen
                )
        else:
            logger.info(f"Group '{name}' in {scope} is dynamic/empty, skipping.")
            member_skips.append({"member": name, "scope": scope, "reason": "dynamic/empty group"})
    return results


def ensure_tag(container: Union[Panorama, DeviceGroup], tag_name: str):
    existing = {t.name: t for t in (Tag.refreshall(container, add=False) or [])}
    if tag_name in existing:
        logger.debug(f"Tag '{tag_name}' already exists in scope {container}.")
        return existing[tag_name]
    logger.info(f"Creating tag '{tag_name}' in {container}.")
    t = Tag(name=tag_name)
    container.add(t)
    limiter.wait()
    t.create()
    return t


def tag_objects_by_scope(
    pano: Panorama,
    local_container: Optional[DeviceGroup],
    pairs: Set[Tuple[str, str]],
    tag_name: str,
    target_group: str,
    target_scope: str
) -> Tuple[int, int, List[Dict[str, str]]]:
    obj_map_shared, _ = load_maps(pano)
    obj_map_local, _ = ({}, {})
    if local_container:
        obj_map_local, _ = load_maps(local_container)

    ensured = {'shared': False, 'local': False}
    updated, total = 0, 0
    outcomes: List[Dict[str, str]] = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for name, scope in sorted(pairs):
        total += 1
        obj = None
        container = pano if scope == 'shared' else local_container
        obj = (obj_map_shared if scope == 'shared' else obj_map_local).get(name)

        if not obj:
            logger.warning(f"Object '{name}' not found in scope {scope}.")
            outcomes.append({
                "object": name, "scope": scope, "status": "not tagged",
                "reason": "object not found", "tag_name": tag_name,
                "target_group": target_group, "target_scope": target_scope,
                "timestamp": timestamp
            })
            continue

        if not ensured[scope]:
            ensure_tag(container, tag_name)
            ensured[scope] = True

        tags = list(obj.tag or [])
        if tag_name in tags:
            logger.info(f"'{name}' already had tag '{tag_name}' (scope: {scope}).")
            outcomes.append({
                "object": name, "scope": scope, "status": "not tagged", "reason": "already had tag",
                "tag_name": tag_name, "target_group": target_group, "target_scope": target_scope,
                "timestamp": timestamp
            })
            continue

        tags.append(tag_name)
        obj.tag = tags
        limiter.wait()
        obj.apply()
        updated += 1
        logger.info(f"Tagged '{name}' (scope: {scope}).")

        outcomes.append({
            "object": name, "scope": scope, "status": "tagged", "reason": "",
            "tag_name": tag_name, "target_group": target_group,
            "target_scope": target_scope, "timestamp": timestamp
        })
    return updated, total, outcomes


# -------------------------
# Main
# -------------------------
def main():
    try:
        pano = connect_panorama()
        container = get_scope_container(pano, TARGET_SCOPE)
        scope_label = "Shared" if isinstance(container, Panorama) else f"Device Group '{container.name}'"

        target_group = find_static_group(container, TARGET_STATIC_GROUP)
        if not target_group:
            logger.error(f"Group '{TARGET_STATIC_GROUP}' not found in {scope_label}.")
            sys.exit(1)

        if target_group.static_value is None:
            logger.error(f"Group '{TARGET_STATIC_GROUP}' is not STATIC.")
            sys.exit(1)

        obj_map_local, grp_map_local = load_maps(container)
        obj_map_shared, grp_map_shared = load_maps(pano) if not isinstance(container, Panorama) else (obj_map_local, grp_map_local)

        member_skips: List[Dict[str, str]] = []
        pairs = resolve_member_to_object_pairs(
            TARGET_STATIC_GROUP, obj_map_local, grp_map_local, obj_map_shared, grp_map_shared, member_skips
        )

        local_container = None if isinstance(container, Panorama) else container
        updated, total, outcomes = tag_objects_by_scope(
            pano, local_container, pairs, DYNAMIC_MATCH_TAG, TARGET_STATIC_GROUP, TARGET_SCOPE
        )

        # Add skipped members to CSV
        for skip in member_skips:
            outcomes.append({
                "object": skip["member"], "scope": skip["scope"], "status": "not tagged",
                "reason": skip["reason"], "tag_name": DYNAMIC_MATCH_TAG,
                "target_group": TARGET_STATIC_GROUP, "target_scope": TARGET_SCOPE,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

        csv_file = f"panorama_tagging_report_{TARGET_STATIC_GROUP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        pd.DataFrame(outcomes).to_csv(csv_file, index=False)
        logger.info(f"CSV report saved: {csv_file}")

        logger.info(f"✅ Tagged {updated}/{total} objects successfully.")
        logger.info(f"⚙️  Candidate config only. Commit + Push required on Panorama.")
        logger.info(f"Rate limit: {MAX_RPS} ops/sec, batch={BATCH_SIZE}, pause={BATCH_PAUSE_SEC}s.")

    except PanDeviceError as e:
        logger.error(f"PAN-OS API error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Script aborted by user.")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
