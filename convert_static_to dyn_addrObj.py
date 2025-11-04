#!/usr/bin/env python3
"""
Panorama (strict, no-commit) tagging script with CSV audit logging.

✅ What it does:
  - Expands nested STATIC Address Groups recursively (cycle-protected).
  - Tags all Address Objects (Shared + DG) that belong to the target group.
  - Skips dynamic groups, missing members, or objects that already have the tag.
  - Writes detailed results to both console and CSV file for audit tracking.

🧾 CSV Report Fields:
  object | scope | status | reason | tag_name | target_group | target_scope | timestamp

⚙️ Requirements:
  pip install pan-os-python pandas
"""

import sys
import getpass
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


# -------------------------
# Helper functions
# -------------------------
def connect_panorama() -> Panorama:
    """Connect to Panorama."""
    try:
        pano = Panorama(hostname=PANORAMA_IP, api_username=USERNAME, api_password=PASSWORD)
        return pano
    except Exception as e:
        sys.exit(f"❌ ERROR: Failed to connect to Panorama: {e}")


def get_scope_container(pano: Panorama, scope_name: str) -> Union[Panorama, DeviceGroup]:
    """Return the container for the chosen scope (Shared or DG)."""
    if scope_name.lower() == "shared":
        return pano

    dgs = DeviceGroup.refreshall(pano, add=False) or []
    for dg in dgs:
        if dg.name == scope_name:
            container = DeviceGroup(name=dg.name)
            pano.add(container)
            return container

    sys.exit(f"❌ ERROR: Device Group '{scope_name}' not found on Panorama.")


def load_maps(container: Union[Panorama, DeviceGroup]) -> Tuple[Dict[str, AddressObject], Dict[str, AddressGroup]]:
    """Load all Address Objects & Groups for the scope."""
    objs = AddressObject.refreshall(container, add=False) or []
    groups = AddressGroup.refreshall(container, add=False) or []
    return ({o.name: o for o in objs}, {g.name: g for g in groups})


def find_static_group(container: Union[Panorama, DeviceGroup], name: str) -> Optional[AddressGroup]:
    """Find a STATIC Address Group by name."""
    groups = AddressGroup.refreshall(container, add=False) or []
    for g in groups:
        if g.name == name:
            return g
    return None


# ---------- Recursive resolution ----------
def resolve_member_to_object_pairs(
    member_name: str,
    obj_map_local: Dict[str, AddressObject],
    grp_map_local: Dict[str, AddressGroup],
    obj_map_shared: Dict[str, AddressObject],
    grp_map_shared: Dict[str, AddressGroup],
    member_skips: List[Dict[str, str]],
    seen: Optional[Set[Tuple[str, str]]] = None,
) -> Set[Tuple[str, str]]:
    """Resolve a member name into AddressObject tuples (name, scope)."""
    if seen is None:
        seen = set()

    identities = []
    if member_name in obj_map_local or member_name in grp_map_local:
        identities.append((member_name, 'local'))
    if member_name in obj_map_shared or member_name in grp_map_shared:
        identities.append((member_name, 'shared'))

    if not identities:
        member_skips.append({"member": member_name, "scope": "unknown", "reason": "not found"})
        return set()

    results: Set[Tuple[str, str]] = set()
    for name, scope in identities:
        identity = (name, scope)
        if identity in seen:
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
            member_skips.append({"member": name, "scope": scope, "reason": "dynamic/empty group"})
    return results


def collect_object_pairs_from_group(
    group: AddressGroup,
    obj_map_local: Dict[str, AddressObject],
    grp_map_local: Dict[str, AddressGroup],
    obj_map_shared: Dict[str, AddressObject],
    grp_map_shared: Dict[str, AddressGroup],
    member_skips: List[Dict[str, str]],
) -> Set[Tuple[str, str]]:
    """Expand the target group to all (object, scope) pairs."""
    pairs: Set[Tuple[str, str]] = set()
    for member in group.static_value or []:
        pairs |= resolve_member_to_object_pairs(
            member, obj_map_local, grp_map_local, obj_map_shared, grp_map_shared, member_skips, seen=set()
        )
    return pairs


def ensure_tag(container: Union[Panorama, DeviceGroup], tag_name: str) -> Tag:
    """Ensure the Tag exists in this scope."""
    existing = {t.name: t for t in (Tag.refreshall(container, add=False) or [])}
    if tag_name in existing:
        return existing[tag_name]
    t = Tag(name=tag_name)
    container.add(t)
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
    """Tag objects and record detailed results."""
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
                    "reason": "resolved to local scope but script running in shared mode",
                    "tag_name": tag_name, "target_group": target_group,
                    "target_scope": target_scope, "timestamp": timestamp
                })
                continue
            obj = obj_map_local.get(name)
            container = local_container

        if not obj:
            outcomes.append({
                "object": name, "scope": scope, "status": "not tagged", "reason": "object not found",
                "tag_name": tag_name, "target_group": target_group,
                "target_scope": target_scope, "timestamp": timestamp
            })
            continue

        if not ensured[scope]:
            ensure_tag(container, tag_name)
            ensured[scope] = True

        tags = list(obj.tag or [])
        if tag_name in tags:
            outcomes.append({
                "object": name, "scope": scope, "status": "not tagged", "reason": "already had tag",
                "tag_name": tag_name, "target_group": target_group,
                "target_scope": target_scope, "timestamp": timestamp
            })
            continue

        tags.append(tag_name)
        obj.tag = tags
        obj.apply()
        updated += 1
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
        print(f"✅ Connected to Panorama {PANORAMA_IP}")

        container = get_scope_container(pano, TARGET_SCOPE)
        scope_label = "Shared" if isinstance(container, Panorama) else f"Device Group '{container.name}'"
        print(f"📍 Operating scope: {scope_label}")

        target_group = find_static_group(container, TARGET_STATIC_GROUP)
        if not target_group:
            sys.exit(f"❌ ERROR: Address Group '{TARGET_STATIC_GROUP}' not found in {scope_label}.")
        if target_group.static_value is None:
            sys.exit(f"❌ ERROR: Address Group '{TARGET_STATIC_GROUP}' is not STATIC (it may be dynamic).")

        obj_map_local, grp_map_local = load_maps(container)
        obj_map_shared, grp_map_shared = load_maps(pano) if not isinstance(container, Panorama) else (obj_map_local, grp_map_local)

        member_skips: List[Dict[str, str]] = []
        pairs = collect_object_pairs_from_group(
            target_group, obj_map_local, grp_map_local, obj_map_shared, grp_map_shared, member_skips
        )

        if not pairs and not member_skips:
            sys.exit("❌ ERROR: No valid AddressObjects resolved from the group hierarchy.")

        local_container = None if isinstance(container, Panorama) else container
        updated, total, outcomes = tag_objects_by_scope(
            pano, local_container, pairs, DYNAMIC_MATCH_TAG, TARGET_STATIC_GROUP, TARGET_SCOPE
        )

        # Include skipped non-object members in CSV
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for skip in member_skips:
            outcomes.append({
                "object": skip["member"], "scope": skip["scope"], "status": "not tagged",
                "reason": skip["reason"], "tag_name": DYNAMIC_MATCH_TAG,
                "target_group": TARGET_STATIC_GROUP, "target_scope": TARGET_SCOPE,
                "timestamp": timestamp
            })

        # ✅ CSV Output
        csv_filename = f"panorama_tagging_report_{TARGET_STATIC_GROUP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df = pd.DataFrame(outcomes)
        df.to_csv(csv_filename, index=False)

        # Console summary
        print("\n==================== Tagging Summary ====================")
        print(f"Target Group: {TARGET_STATIC_GROUP}")
        print(f"Scope: {scope_label}")
        print(f"Tag applied: {DYNAMIC_MATCH_TAG}")
        print(f"Total objects processed: {total}")
        print(f"Successfully tagged: {updated}")
        print(f"Skipped or unchanged: {total - updated}")
        print("========================================================\n")
        print(f"📄 CSV report saved as: {csv_filename}")
        print("⚠️  NOTE: All changes are in Panorama's candidate configuration only.")
        print("📝  You must COMMIT and PUSH in Panorama to enforce these changes.")
        print("🎉 Done.")

    except PanDeviceError as e:
        sys.exit(f"❌ PAN-OS / Panorama API error: {e}")
    except KeyboardInterrupt:
        sys.exit("🛑 Aborted by user.")
    except Exception as e:
        sys.exit(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()
