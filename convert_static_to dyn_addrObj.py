"""
This script automates the process of tagging static address objects that are in a static address group located in a target Panorama device group.
It was created to assist with the adoption of Dynamic Address Groups or DAGs.

Minimum Software Requirements:
- Python 3.9.5
- PAN-OS SDK 1.12.0
- PAN-OS Software Version: 11.X.X
- Pandas 2.2.2

This script:
  - Expands a STATIC Address Group (recursively), following nested STATIC groups.
  - Identifies every Address Object that belongs to that group (in the chosen scope and Shared).
  - Ensures a Tag exists in the correct scope (Shared or Device Group).
  - Adds that Tag to each resolved Address Object.
  - Applies changes to the Panorama *candidate configuration only* (no commit/push).
  - Throttles write operations (rate limiting + batch pauses) to avoid overloading Panorama CPU.
  - Logs actions to console (and optional file) and writes a CSV audit report.

Key points for Network Engineers:
  - "Read" operations use the API to retrieve configuration data; they do NOT change the device configuration.
  - "Write" operations (Tag.create / AddressObject.apply) modify Panorama candidate configuration.
  - Nothing hits dataplane/rules until you "Commit" on Panorama and "Push to devices" from the Panorama GUI or CLI.

Author: Quincy McKinney  
"""

# =========================
# [Python + Panorama] Standard imports and SDK bindings.
# Python: we import standard libs, logging, pandas for CSV.
# Panorama: we import pan-os-python models that map to Panorama config elements.
# =========================
import sys
import time
import getpass
import logging
import pandas as pd
from datetime import datetime
from typing import Optional, Set, Dict, Tuple, Union, List

from panos.panorama import Panorama, DeviceGroup
from panos.objects import AddressObject, AddressGroup, Tag
from panos.errors import PanDeviceError


# =========================
# BLOCK: User Input (Strict Validation)
#
# Python: Prompt for all required inputs and fail fast on blanks/invalid values.
# Panorama: No API call is executed yet; this is purely local input validation.
# =========================
USERNAME = input("Panorama username: ").strip()
if not USERNAME:
    sys.exit("ERROR: Username cannot be blank.")

PASSWORD = getpass.getpass("Panorama password: ")
if not PASSWORD:
    sys.exit("ERROR: Password cannot be blank.")

PANORAMA_IP = input("Panorama management IP / FQDN: ").strip()
if not PANORAMA_IP:
    sys.exit("ERROR: Panorama management IP cannot be blank.")

TARGET_SCOPE = input("Target scope (Device Group name OR 'shared'): ").strip()
if not TARGET_SCOPE:
    sys.exit("ERROR: Target scope cannot be blank.")

TARGET_STATIC_GROUP = input("Target STATIC Address Group name (must exist in the chosen scope): ").strip()
if not TARGET_STATIC_GROUP:
    sys.exit("ERROR: Address Group name cannot be blank.")

DYNAMIC_MATCH_TAG = input("Tag to apply to Address Objects: ").strip()
if not DYNAMIC_MATCH_TAG:
    sys.exit("ERROR: Tag name cannot be blank.")

# Rate limiting configuration (controls API write pacing to keep Panorama CPU stable).
try:
    MAX_RPS = float(input("Max write operations per second (e.g., 2): ").strip())
    if MAX_RPS <= 0:
        raise ValueError
except ValueError:
    sys.exit("ERROR: Max write operations per second must be positive.")

try:
    BATCH_SIZE = int(input("Batch size before pausing (e.g., 20): ").strip())
    if BATCH_SIZE <= 0:
        raise ValueError
except ValueError:
    sys.exit("ERROR: Batch size must be a positive integer.")

try:
    BATCH_PAUSE_SEC = float(input("Batch pause duration in seconds (e.g., 5): ").strip())
    if BATCH_PAUSE_SEC < 0:
        raise ValueError
except ValueError:
    sys.exit("ERROR: Batch pause duration must be non-negative.")

LOG_FILE = input("Optional log file path (press Enter to skip): ").strip()


# =========================
# BLOCK: Logging Configuration
#
# Python: Configure structured logging to console (and optional log file).
# Panorama: No device impact; this is local observability for the user.
# =========================
logger = logging.getLogger("PanoramaTagger")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%H:%M:%S"))
logger.addHandler(console_handler)

if LOG_FILE:
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(file_handler)
    logger.info(f"Logging to file: {LOG_FILE}")


# =========================
# BLOCK: Rate Limiter
#
# Python: Implements per-operation spacing and batch pauses between writes.
# Panorama: Reduces load on configd/API when applying many small changes.
# =========================
class RateLimiter:
    """Rate limits write operations to Panorama for stability."""
    def __init__(self, rps: float, batch_size: int, batch_pause: float):
        self.min_interval = 1.0 / rps
        self.last_ts = 0.0
        self.batch_size = batch_size
        self.batch_pause = batch_pause
        self.counter = 0

    def wait(self):
        # Per-operation spacing
        now = time.monotonic()
        delta = now - self.last_ts
        if self.last_ts != 0.0 and delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self.last_ts = time.monotonic()

        # Batch pause after N writes
        self.counter += 1
        if self.counter >= self.batch_size:
            if self.batch_pause > 0:
                logger.info(f"Batch limit reached ({self.batch_size} operations). Pausing for {self.batch_pause} seconds.")
                time.sleep(self.batch_pause)
            self.counter = 0


limiter = RateLimiter(MAX_RPS, BATCH_SIZE, BATCH_PAUSE_SEC)


# =========================
# BLOCK: Helper Functions (Connectivity, Scoping, Reads)
#
# Python: Build Panorama session, choose working scope (Shared or Device Group),
#         and load configuration data into local Python structures.
# Panorama: Uses read-only API calls (refreshall) to fetch existing config.
# =========================
def connect_panorama() -> Panorama:
    """
    Python: Instantiate Panorama client object (real auth on first API call).
    Panorama: On first SDK action, authenticate and obtain API key.
    """
    try:
        logger.info(f"Connecting to Panorama at {PANORAMA_IP}...")
        pano = Panorama(hostname=PANORAMA_IP, api_username=USERNAME, api_password=PASSWORD)
        return pano
    except Exception as e:
        logger.error(f"Failed to connect to Panorama: {e}")
        sys.exit(1)


def get_scope_container(pano: Panorama, scope_name: str) -> Union[Panorama, DeviceGroup]:
    """
    Python: Select the config container we will operate in.
      - 'shared' → operate at /config/shared
      - DeviceGroup name → operate under that DG
    Panorama: No writes; this binds the SDK to the desired subtree.
    """
    if scope_name.lower() == "shared":
        logger.info("Operating in Shared scope.")
        return pano

    dgs = DeviceGroup.refreshall(pano, add=False) or []  # read-only
    for dg in dgs:
        if dg.name == scope_name:
            container = DeviceGroup(name=dg.name)
            pano.add(container)  # bind child node
            logger.info(f"Operating in Device Group: {scope_name}")
            return container
    sys.exit(f"ERROR: Device Group '{scope_name}' not found on Panorama.")


def load_maps(container: Union[Panorama, DeviceGroup]) -> Tuple[Dict[str, AddressObject], Dict[str, AddressGroup]]:
    """
    Python: Pull all Address Objects and Address Groups from the scope and index by name.
    Panorama: Read-only API — no changes to candidate/running config.
    """
    objs = AddressObject.refreshall(container, add=False) or []
    groups = AddressGroup.refreshall(container, add=False) or []
    return ({o.name: o for o in objs}, {g.name: g for g in groups})


def find_static_group(container: Union[Panorama, DeviceGroup], name: str) -> Optional[AddressGroup]:
    """
    Python: Find an Address Group by name (for existence and later type check).
    Panorama: Read-only API to fetch group entries.
    """
    groups = AddressGroup.refreshall(container, add=False) or []
    for g in groups:
        if g.name == name:
            return g
    return None


# =========================
# BLOCK: Resolution (Static Group Expansion)
#
# Python: Recursively walk nested STATIC groups to produce the set of Address Objects.
#         We examine both the selected scope and Shared (to handle shared objects referenced by DG).
# Panorama: Purely read-only; traverses data we already fetched via refreshall().
# =========================
def resolve_member_to_object_pairs(
    member_name: str,
    obj_map_local: Dict[str, AddressObject],
    grp_map_local: Dict[str, AddressGroup],
    obj_map_shared: Dict[str, AddressObject],
    grp_map_shared: Dict[str, AddressGroup],
    member_skips: List[Dict[str, str]],
    seen: Optional[Set[Tuple[str, str]]] = None,
) -> Set[Tuple[str, str]]:
    """
    Return set of (address_object_name, 'local'|'shared') for a member that may be an object or a group.
    - Prefers local (DG) entries on name collision; otherwise uses Shared.
    - Skips dynamic/empty groups and records why.
    - Uses cycle protection to avoid infinite recursion on misconfigured groups.
    """
    if seen is None:
        seen = set()

    identities = []
    if member_name in obj_map_local or member_name in grp_map_local:
        identities.append((member_name, 'local'))
    if member_name in obj_map_shared or member_name in grp_map_shared:
        identities.append((member_name, 'shared'))

    if not identities:
        logger.warning(f"Member '{member_name}' not found in local/shared scopes.")
        member_skips.append({"member": member_name, "scope": "unknown", "reason": "not found"})
        return set()

    results: Set[Tuple[str, str]] = set()
    for name, scope in identities:
        identity = (name, scope)
        if identity in seen:
            logger.warning(f"Cyclic reference detected on '{name}' ({scope}); skipping.")
            member_skips.append({"member": name, "scope": scope, "reason": "cyclic reference"})
            continue
        seen.add(identity)

        # If it is directly an Address Object in this scope
        if scope == 'local' and name in obj_map_local:
            results.add((name, 'local'))
            continue
        if scope == 'shared' and name in obj_map_shared:
            results.add((name, 'shared'))
            continue

        # Otherwise, treat as a group and recurse only if STATIC
        group = grp_map_local.get(name) if scope == 'local' else grp_map_shared.get(name)
        if not group:
            continue
        if group.static_value:
            for child in group.static_value:
                results |= resolve_member_to_object_pairs(
                    child, obj_map_local, grp_map_local, obj_map_shared, grp_map_shared, member_skips, seen=seen
                )
        else:
            logger.info(f"Group '{name}' in {scope} is dynamic or empty; skipping.")
            member_skips.append({"member": name, "scope": scope, "reason": "dynamic/empty group"})
    return results


# =========================
# BLOCK: Ensure Tag in Scope
#
# Python: If the Tag does not exist in the current scope, create it once.
# Panorama: Tag.create() writes to the candidate configuration (no commit here).
# =========================
def ensure_tag(container: Union[Panorama, DeviceGroup], tag_name: str):
    existing = {t.name: t for t in (Tag.refreshall(container, add=False) or [])}
    if tag_name in existing:
        logger.debug(f"Tag '{tag_name}' already exists in scope.")
        return existing[tag_name]
    logger.info(f"Creating tag '{tag_name}' in {container}.")
    t = Tag(name=tag_name)
    container.add(t)
    limiter.wait()   # throttle the write
    t.create()       # candidate config only
    return t


# =========================
# BLOCK: Tagging Pass (Writes)
#
# Python: For each resolved Address Object (with its origin scope), ensure the Tag exists,
#         then update the object's tag list and call .apply().
# Panorama: AddressObject.apply() writes to the candidate config in that scope.
#           No policy/dataplane impact until manual Commit and Push.
# =========================
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

        if scope == 'shared':
            obj = obj_map_shared.get(name)
            container = pano
        else:
            if not local_container:
                outcomes.append({
                    "object": name, "scope": "local", "status": "not tagged",
                    "reason": "local scope object, but script running in shared mode",
                    "tag_name": tag_name, "target_group": target_group,
                    "target_scope": target_scope, "timestamp": timestamp
                })
                continue
            obj = obj_map_local.get(name)
            container = local_container

        if not obj:
            outcomes.append({
                "object": name, "scope": scope, "status": "not tagged",
                "reason": "object not found", "tag_name": tag_name,
                "target_group": target_group, "target_scope": target_scope,
                "timestamp": timestamp
            })
            continue

        if not ensured[scope]:
            ensure_tag(container, tag_name)  # may create (candidate write)
            ensured[scope] = True

        tags = list(obj.tag or [])
        if tag_name in tags:
            outcomes.append({
                "object": name, "scope": scope, "status": "not tagged",
                "reason": "already had tag", "tag_name": tag_name,
                "target_group": target_group, "target_scope": target_scope,
                "timestamp": timestamp
            })
            continue

        # Candidate-config write, rate-limited
        tags.append(tag_name)
        obj.tag = tags
        limiter.wait()
        obj.apply()
        updated += 1
        outcomes.append({
            "object": name, "scope": scope, "status": "tagged", "reason": "",
            "tag_name": tag_name, "target_group": target_group,
            "target_scope": target_scope, "timestamp": timestamp
        })

    return updated, total, outcomes


# =========================
# BLOCK: Main Orchestration
#
# Python: Executes the full workflow in a clear sequence.
# Panorama: Performs reads first, then controlled candidate writes, no commit/push.
# =========================
def main():
    try:
        # 1) Connect to Panorama (auth happens on first SDK call)
        pano = connect_panorama()

        # 2) Select operational scope (Shared or specific Device Group)
        container = get_scope_container(pano, TARGET_SCOPE)
        scope_label = "Shared" if isinstance(container, Panorama) else f"Device Group '{container.name}'"

        # 3) Validate the target Address Group and confirm it is STATIC
        target_group = find_static_group(container, TARGET_STATIC_GROUP)
        if not target_group:
            logger.error(f"Group '{TARGET_STATIC_GROUP}' not found in {scope_label}.")
            sys.exit(1)
        if target_group.static_value is None:
            logger.error(f"Group '{TARGET_STATIC_GROUP}' is not STATIC (it may be dynamic).")
            sys.exit(1)
        logger.info(f"Found STATIC group '{TARGET_STATIC_GROUP}' with {len(target_group.static_value)} direct members.")

        # 4) Load local + shared maps to support cross-scope resolution
        obj_map_local, grp_map_local = load_maps(container)
        obj_map_shared, grp_map_shared = load_maps(pano) if not isinstance(container, Panorama) else (obj_map_local, grp_map_local)

        # 5) Expand the group recursively into concrete Address Objects
        member_skips: List[Dict[str, str]] = []
        pairs = resolve_member_to_object_pairs(
            TARGET_STATIC_GROUP,  # start from the group name itself; resolver descends into static members
            obj_map_local, grp_map_local,
            obj_map_shared, grp_map_shared,
            member_skips
        )

        if not pairs and not member_skips:
            logger.error("No valid AddressObjects resolved from the group hierarchy.")
            sys.exit(1)

        # 6) Tag each object in its proper scope (candidate writes only, rate-limited)
        local_container = None if isinstance(container, Panorama) else container
        updated, total, outcomes = tag_objects_by_scope(
            pano, local_container, pairs, DYNAMIC_MATCH_TAG, TARGET_STATIC_GROUP, TARGET_SCOPE
        )

        # 7) Include non-object resolution skips in the audit output
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for skip in member_skips:
            outcomes.append({
                "object": skip["member"], "scope": skip["scope"], "status": "not tagged",
                "reason": skip["reason"], "tag_name": DYNAMIC_MATCH_TAG,
                "target_group": TARGET_STATIC_GROUP, "target_scope": TARGET_SCOPE,
                "timestamp": timestamp
            })

        # 8) Write CSV audit report (local file; no Panorama impact)
        csv_file = f"panorama_tagging_report_{TARGET_STATIC_GROUP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        pd.DataFrame(outcomes, columns=[
            "object", "scope", "status", "reason", "tag_name", "target_group", "target_scope", "timestamp"
        ]).to_csv(csv_file, index=False)
        logger.info(f"CSV report saved: {csv_file}")

        # 9) Console summary and operator reminders
        shared_count = len({n for (n, s) in pairs if s == 'shared'})
        local_count = len({n for (n, s) in pairs if s == 'local'})
        logger.info("===== Tagging Summary =====")
        logger.info(f"Target Group: {TARGET_STATIC_GROUP}")
        logger.info(f"Scope: {scope_label}")
        logger.info(f"Tag applied: {DYNAMIC_MATCH_TAG}")
        logger.info(f"Resolved objects — Shared: {shared_count}, Local: {local_count}, Total: {len(pairs)}")
        logger.info(f"Attempted writes: {total} | Successfully tagged: {updated} | Skipped/unchanged: {total - updated}")
        logger.info(f"Rate limit: {MAX_RPS} ops/sec | Batch: {BATCH_SIZE} | Pause: {BATCH_PAUSE_SEC}s")
        logger.info("NOTE: Changes are in the candidate configuration only. Commit and Push from Panorama to enforce.")

    except PanDeviceError as e:
        logger.error(f"PAN-OS / Panorama API error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Script aborted by user.")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
