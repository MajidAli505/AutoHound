# AutoHound

**BloodHound, but automatic.**

BloodHound gives you a graph — then *you* have to know Cypher, write queries, and hunt for attack paths by hand. AutoHound does that work for you: give it SharpHound / BloodHound data and it automatically finds **every privilege escalation path**, explains how to exploit each one step by step, and builds you a clean dashboard to follow.

No queries. No clicking. No Neo4j / Docker. Pure Python standard library — zero dependencies.

![Version](https://img.shields.io/badge/version-1.4-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-17%20passing-brightgreen)

## Quick start

```bash
# 1. Collect data on a domain-joined Windows machine
SharpHound.exe -c All

# 2. Analyse it
python3 autohound.py --input sharphound.zip

# 3. Open the dashboard
#    -> report folder contains dashboard.html, report.md, report.json
```

Full walkthrough: [QUICKSTART.md](QUICKSTART.md)

Try it instantly on the bundled sample domain:

```bash
python3 autohound.py --input sample_data/sample_all.json --out sample_report
```

## What it does automatically

1. **Parses** SharpHound / BloodHound.py JSON — a single file, multiple files, a folder, or a `.zip`. Supports Users, Groups, Computers, Domains, GPOs and OUs, with edges from Members, PrimaryGroupSID, Aces, LocalAdmins, Sessions, PrivilegedSessions, RemoteDesktopUsers, PSRemoteUsers, AllowedToDelegate, AllowedToAct and ChildObjects.
2. **Builds the attack graph** and identifies Tier-Zero / high-value targets automatically (Domain Admins, Enterprise Admins, well-known RIDs, `highvalue=True`, domain controllers).
3. **Finds every path** from every principal to Tier-Zero with a single reverse-BFS — a real 5,159-node / 66,769-edge domain analyses in ~1.7 seconds.
4. **Generates findings with no queries needed:** DCSync rights, Kerberoastable and AS-REP roastable accounts, unconstrained delegation, dangerous ACLs, and GPO abuse chains (including GPO-derived local admins).
5. **Writes the exploitation playbook for every path** — numbered steps with the real usernames, groups, computers, DC and GPO GUIDs filled in, the exact command to run (BloodyAD, SharpGPOAbuse, secretsdump, GetUserSPNs…), why the step works, and the identity you hold after it. Only credentials are placeholders — no real password is ever written to a report.
6. **Scores and verifies itself** — every path gets a confidence score from per-edge reliability, alternative routes are counted (one blocked hop doesn't kill the attack), and every reported path is re-walked against the raw edge set before the report is written.
7. **Flags collection gaps honestly** — a data-quality section reports missing session data, unresolved foreign principals, disabled accounts, and LAPS coverage, so a gap is never mistaken for a clean result.

## The dashboard

Every run produces a standalone, offline `dashboard.html` (single file, no external assets):

- **Path Explorer** — privilege-escalation paths only, ranked by importance (paths shared by thousands of principals beat one-hop paths from accounts that are already admin), under a slim header band with live summary stats (objects analysed / escalation paths / checked accounts)
- **Beginner mode by default** — permissions in plain words, technical names one toggle away in Expert mode; confidence and other numbers are tucked into a collapsed details section
- **"Before you start" checklist** per path, per-step done checkboxes with a progress bar, and an "I start from" selector listing **every** account — selecting an account with no path shows an honest "No path from X" panel with what that account does have, instead of a blank screen
- **"Checked — no full path" section** — accounts whose power dead-ends in the data (local admin of a workstation with no onward hop, half of the DCSync rights, roastable accounts) are listed with their reasons, so no account ever looks "missing"
- **Multi-dataset support** — feed it several SharpHound zips (one per domain / project) and get one dashboard with a dataset switcher and a report folder per dataset (`--separate` / `--combine` to control this)

## Tested on real data

TryHackMe `ZA.TRYHACKME.LOC` (SharpHound v4): **5,045 users, 5,159 nodes, 66,769 edges in 1.7s.**

Headline finding: a chain shared by **5,002 principals** (confidence 77.6%, 13 alternative routes) —

```
Domain Users → GenericWrite on IT SUPPORT → ForceChangePassword on a Tier 2 admin → Tier 2 Admins
```

Also found: SVCSERVMAN GPO abuse → THMSERVER2, a Kerberoastable service account, and confirmation that DCSync was held only by already-admin groups.

```bash
python3 test_autohound.py   # 17 automated tests, all passing
```

## Legal use

AutoHound is for authorised security assessments and lab environments only. Only analyse data from domains you own or have explicit permission to test.

## Author

**Majid Ali** — [@MajidAli505](https://github.com/MajidAli505)
