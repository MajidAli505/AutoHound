# AutoHound v1.2 — Quick Start

AutoHound does one thing: you give it SharpHound / BloodHound data, and it finds
**every privilege escalation path for you** — no queries, no clicking around in
BloodHound. It then builds a simple English playbook you can follow step by step.

You need only one thing installed: **Python 3**. Keep `autohound.py` and
`dashboard.py` in the same folder.

## Step 1 — Collect the data (on a domain-joined Windows machine)

```
SharpHound.exe -c All
```

Or from Linux (BloodHound.py):

```
bloodhound-python -d DOMAIN.LOCAL -u USER -p PASS -ns <DC_IP> -c All
```

You get a .zip file (or a folder of JSON files). That file is the input.

## Step 2 — Run AutoHound

```
python3 autohound.py --input sharphound_data.zip
```

That's it. AutoHound reads everything, builds the attack graph, finds all paths
to Tier-Zero and to the admin groups, checks every path it reports against the
raw data, and writes a report folder.

## Step 3 — Open the dashboard

Open `autohound_report/dashboard.html` in any browser. It works fully offline.

The dashboard is a clean Path Explorer — it shows **privilege-escalation paths
only**: a list of paths on the left (filter: All / Tier-Zero / Admin groups),
and the selected path on the right as clear steps: the instruction, why it
works, the exact command, and what you become after the step. No graph, no
extra sections.

New in v1.2 (built for beginners):

- **"I start from" selector** (top right): pick your own account and the list
  shows only the paths that start from it.
- **Beginner mode is the default**: permissions are written in plain words
  ("can change / edit") instead of jargon like GenericWrite. Switch to
  **Expert** in the same panel when you want the technical names and numbers.
- **"Before you start" checklist** on every path: the account you need, the
  tools used in its commands, and the one step to watch out for.
- **Progress tracking**: tick "Mark step as done" while you follow a path;
  the progress bar at the top fills up.
- **Numbers are tucked away** under "Numbers & technical details" — the main
  screen shows only start, step count and end result.

## Many SharpHound files? One dashboard for all of them

If you have several collections (for example one .zip per domain), pass them
all in one run — multiple .zip files are treated as separate datasets:

```
python3 autohound.py --input domain1.zip --input domain2.zip --out reports
```

You get one report folder per dataset under `reports/`, plus ONE
`reports/dashboard.html` with a **dataset switcher** at the top right: pick a
collection, and its paths appear. Use `--separate` to force this behaviour for
folder/JSON inputs too, or `--combine` to merge inputs into one graph (for
example `users.json` + `groups.json` that belong to a single collection).

`report.md` has the full findings in text form (including DCSync, GPO abuse,
Kerberoastable accounts and remediation), and `report.json` has them in
machine-readable form.

## Try it on the demo data first

```
python3 autohound.py --input sample_data/sample_all.json --out demo
```

## Good to know

- **Sessions matter.** If the collection has no session data, attacks that need a
  live admin session on a machine are invisible. AutoHound tells you this in the
  report instead of pretending the domain is safe. Always collect with `-c All`.
- **Placeholders:** in commands, replace `<YOUR_USER>`, `<PASS>` and
  `<NEW_PASSWORD>` with your own values.
- For authorized labs and pentests only.
