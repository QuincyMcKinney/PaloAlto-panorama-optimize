#!/usr/bin/env python3
"""
Panorama (strict, no-commit):
  Tag all Address Objects that are (directly or indirectly) members of a STATIC Address Group
  that exists in a chosen scope (Device Group by name OR 'shared'). While expanding that group,
  this script also recognizes and correctly tags Address Objects that live in the Shared scope,
  even when referenced by a Device Group's address group.

Operational stance:
  - Strict inputs (no defaults, blanks or unknown values cause immediate exit).
  - Recursively expands nested STATIC groups (cycle-protected).
  - For every resolved object, determines whether it belongs to the Device Group scope or Shared scope.
  - Ensures the tag exists in the proper scope before applying it to the object in that same scope.
  - No Dynamic Address Group creation and NO commit/push (candidate config only).

Requirements:
  pip install pan-os-python
"""

import sys
import getpass
from typing import Optional, Set, Dict, Tuple, Union

# Panorama SDK models
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

# Scope selector:
#  - Enter 'shared' to operate in the Shared scope
#  - Or enter the exact Device Group name (case-sensitive)
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
# Helpers
# -------------------------
def connect_panorama() -> Panorama:
    """
    Connect to Panorama (session manager). Actual auth occurs on first API call.
    """
    try:
        pano = Panorama(hostname=PANORAMA_IP, api_username=USERNAME, api_password=PASSWORD)
        return pano
    except Exception as e:
        sys.exit(f"❌ ERROR: Failed to connect to Panorama: {e}")


def get_scope_container(pano: Panorama, scope_name: str) -> Union[Panorama, DeviceGroup]:
    """
    Return the container object for the requested scope:
      - 'shared'  → the Panorama object itself
      - <DG name> → a DeviceGroup child bound to Panorama
    """
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
    """
    Pull all Address Objects & Address Groups in a given scope into dictionaries by name.
    (Read-only; no config changes.)
    """
    objs = AddressObject.refreshall(container, add=False) or []
    groups = AddressGroup.refreshall(container, add=False) or []
    return ({o.name: o for o in objs}, {g.name: g for g in groups})


def find_static_group(container: Union[Panorama, DeviceGroup], name: str) -> Optional[AddressGroup]:
    """
    Look up a STATIC Address Group by exact name in the chosen scope.
    (If it's dynamic, .static_value will be None; we error on that later.)
    """
    groups = AddressGroup.refreshall(container, add=False) or []
    for g in groups:
        if g.name == name:
            return g
    return None


# ---------- Resolution across both local scope and shared ----------
# We need to be able to resolve a member by name whether it lives in the local scope (DG)
# or in Shared. We return (name, scope_str) pairs so we can later tag in the proper place.
def resolve_member_to_object_pairs(
    member_name: str,
    obj_map_local: Dict[str, AddressObject],
    grp_map_local: Dict[str, AddressGroup],
    obj_map_shared: Dict[str, AddressObject],
    grp_map_shared: Dict[str, AddressGroup],
    seen: Optional[Set[Tuple[str, str]]] = None,
) -> Set[Tuple[str, str]]:
    """
    Resolve a single member (object or group name) into final Address Object pairs:
      returns a set of tuples: {(object_name, 'local'|'shared'), ...}

    Resolution order:
      - Prefer local scope for name collisions; otherwise use shared.
      - Recurse only into STATIC groups. Dynamic groups are runtime constructs.
    """
    if seen is None:
        seen = set()

    # Compose two possible identities for cycle detection: local/shared
    identities = []
    if member_name in obj_map_local or member_name in grp_map_local:
        identities.append((member_name, 'local'))
    if member_name in obj_map_shared or member_name in grp_map_shared:
        identities.append((member_name, 'shared'))

    # If the member doesn't exist in either map, warn and stop.
    if not identities:
        print(f"⚠️  WARNING: Member '{member_name}' not found as an AddressObject or AddressGroup in local or shared scope.")
        return set()

    results: Set[Tuple[str, str]] = set()

    # Try local first, then shared (so DG overrides shared on name collisions)
    for name, scope in identities:
        identity = (name, scope)
        if identity in seen:
            # Cycle protection
            print(f"⚠️  WARNING: Detected cyclic reference on '{name}' in scope '{scope}', skipping.")
            continue
        # Track this identity to avoid loops
        seen.add(identity)

        # If it's an object in this scope, we are done for this branch
        if scope == 'local' and name in obj_map_local:
            results.add((name, 'local'))
            continue
        if scope == 'shared' and name in obj_map_shared:
            results.add((name, 'shared'))
            continue

        # Else, if it's a group in this scope, recurse into its static members
        group = grp_map_local.get(name) if scope == 'local' else grp_map_shared.get(name)
        if group is None:
            # Not a group in this scope; try next identity
            continue

        if group.static_value:
            for child in group.static_value:
                results |= resolve_member_to_object_pairs(
                    child,
                    obj_map_local, grp_map_local,
                    obj_map_shared, grp_map_shared,
                    seen=seen,
                )
        else:
            # Dynamic or empty group; nothing to expand
            print(f"ℹ️  INFO: Member '{name}' in scope '{scope}' is a dynamic/empty group; skipping recursion.")

    return results


def collect_object_pairs_from_group(
    group: AddressGroup,
    obj_map_local: Dict[str, AddressObject],
    grp_map_local: Dict[str, AddressGroup],
    obj_map_shared: Dict[str, AddressObject],
    grp_map_shared: Dict[str, AddressGroup],
) -> Set[Tuple[str, str]]:
    """
    Expand the target STATIC group (which exists in the chosen scope) down to unique
    (object_name, scope_str) pairs, walking nested groups across both local and shared.
    """
    pairs: Set[Tuple[str, str]] = set()
    for member in group.static_value or []:
        pairs |= resolve_member_to_object_pairs(
            member,
            obj_map_local, grp_map_local,
            obj_map_shared, grp_map_shared,
            seen=set(),
        )
    return pairs


def ensure_tag(container: Union[Panorama, DeviceGroup], tag_name: str) -> Tag:
    """
    Ensure a Tag exists in the specified container (Shared or Device Group).
    .create() writes to candidate config only (no commit).
    """
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
) -> Tuple[int, int]:
    """
    Apply tag_name to each Address Object, updating it in the correct scope:
      - ('name', 'shared') → update object under Panorama (Shared)
      - ('name', 'local')  → update object under local_container (Device Group)

    We also ensure the Tag exists in whichever scope each object lives in.
    """
    # Build quick lookup maps again for update handles in each scope
    obj_map_shared, _grp_shared = load_maps(pano)
    obj_map_local, _grp_local = ({}, {})
    if local_container is not None:
        obj_map_local, _grp_local = load_maps(local_container)

    # Cache ensured tags so we don't re-create/check repeatedly
    ensured = {'shared': False, 'local': False}

    updated = 0
    total = 0

    for name, scope in sorted(pairs):
        total += 1

        # Get the object handle in the appropriate scope
        if scope == 'shared':
            obj = obj_map_shared.get(name)
            container = pano
        else:  # 'local'
            if local_container is None:
                print(f"⚠️  WARNING: '{name}' resolved to local scope but no Device Group container was provided.")
                continue
            obj = obj_map_local.get(name)
            container = local_container

        if not obj:
            print(f"⚠️  WARNING: AddressObject '{name}' not found during tagging in scope '{scope}'.")
            continue

        # Ensure the tag exists in that scope once
        if not ensured[scope]:
            ensure_tag(container, tag_name)
            ensured[scope] = True

        # Apply tag if not already present
        current_tags = list(obj.tag or [])
        if tag_name not in current_tags:
            current_tags.append(tag_name)
            obj.tag = current_tags
            obj.apply()   # writes to Panorama candidate config at this scope
            updated += 1

    return updated, total


# -------------------------
# Main
# -------------------------
def main():
    try:
        # 1) Connect
        pano = connect_panorama()
        print(f"✅ Connected to Panorama {PANORAMA_IP}")

        # 2) Scope selection
        container = get_scope_container(pano, TARGET_SCOPE)
        scope_label = "Shared" if isinstance(container, Panorama) else f"Device Group '{container.name}'"
        print(f"📍 Operating scope: {scope_label}")

        # 3) Validate target group exists in THIS scope and is STATIC
        target_group = find_static_group(container, TARGET_STATIC_GROUP)
        if target_group is None:
            sys.exit(f"❌ ERROR: Address Group '{TARGET_STATIC_GROUP}' not found in {scope_label}.")
        if target_group.static_value is None:
            sys.exit(f"❌ ERROR: Address Group '{TARGET_STATIC_GROUP}' is not STATIC (it may be dynamic).")

        print(f"🔍 Found STATIC group '{TARGET_STATIC_GROUP}' with {len(target_group.static_value)} direct members.")

        # 4) Build maps for BOTH the chosen scope and Shared
        #    - Local maps reflect objects/groups defined inside the DG (or Shared if scope==Shared)
        #    - Shared maps reflect objects/groups in Panorama Shared
        if isinstance(container, Panorama):
            # If scope is Shared, "local" == shared; keep maps distinct for consistent code paths
            obj_map_local, grp_map_local = load_maps(container)
            obj_map_shared, grp_map_shared = obj_map_local, grp_map_local
        else:
            obj_map_local, grp_map_local   = load_maps(container)
            obj_map_shared, grp_map_shared = load_maps(pano)

        # 5) Expand nested groups across both maps → (name, scope) pairs
        pairs = collect_object_pairs_from_group(
            target_group,
            obj_map_local, grp_map_local,
            obj_map_shared, grp_map_shared,
        )
        if not pairs:
            sys.exit("❌ ERROR: No valid AddressObjects resolved from the group hierarchy (local/shared).")

        # 6) Tag each object in its proper scope (ensuring the tag exists in that scope first)
        local_container = None if isinstance(container, Panorama) else container
        updated, total = tag_objects_by_scope(pano, local_container, pairs, DYNAMIC_MATCH_TAG)

        # 7) Report
        shared_count = len({n for (n, s) in pairs if s == 'shared'})
        local_count  = len({n for (n, s) in pairs if s == 'local'})
        print(f"📦 Resolved objects — Shared: {shared_count}, Local: {local_count}, Total unique: {len(pairs)}")
        print(f"✅ Tagged {updated}/{total} AddressObject(s) with '{DYNAMIC_MATCH_TAG}' (Panorama candidate config updated).")

        print("\n⚠️  NOTE: Changes are in Panorama's CANDIDATE configuration.")
        print("📝  You must COMMIT on Panorama and PUSH to devices for enforcement.\n")
        print("🎉 Done. No commit/push was performed by this script.")

    except PanDeviceError as e:
        sys.exit(f"❌ PAN-OS / Panorama API error: {e}")
    except KeyboardInterrupt:
        sys.exit("🛑 Aborted by user.")
    except Exception as e:
        sys.exit(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()
