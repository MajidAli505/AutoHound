#!/usr/bin/env python3
"""AutoHound dashboard renderer (v1.1).

One generic Path Explorer for ANY SharpHound/BloodHound collection:
accepts one dataset, or many datasets in a single file (dataset switcher),
and shows ONLY privilege-escalation paths with clear step instructions.
The heavy full-graph payload is stripped before embedding."""
import json
from pathlib import Path

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutoHound — Privilege Escalation Paths</title>
<style>
:root{--bg:#f4f6f8;--panel:#ffffff;--ink:#17202a;--muted:#64748b;--line:#d9e1e8;
--red:#c81e1e;--redbg:#fef2f2;--orange:#b45309;--orangebg:#fff7ed;--green:#15803d;--greenbg:#f0fdf4;
--blue:#1d4ed8;--code:#0b1220;--chip:#eef2f7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1220px;margin:0 auto;padding:22px 18px 42px}
.top{display:flex;justify-content:space-between;gap:18px;align-items:flex-end;flex-wrap:wrap;margin-bottom:14px}
h1{font-size:28px;line-height:1.15;margin:0}h1 span{color:var(--red)}
.tagline{color:var(--muted);margin:5px 0 0;max-width:620px}
.controls{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:12px 14px;min-width:300px;flex:0 1 430px}
.controls label{display:block;font-size:12px;font-weight:700;letter-spacing:.05em;color:var(--muted);text-transform:uppercase;margin-bottom:6px}
select{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:9px;background:#fff;color:var(--ink);font-size:14px}
.meta{font-size:12.5px;color:var(--muted);margin-top:7px}
.toolbar{display:flex;gap:16px;flex-wrap:wrap;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:10px 14px;margin-bottom:14px}
.toolItem{display:flex;align-items:center;gap:8px}
.toolItem label{font-size:11px;font-weight:700;letter-spacing:.05em;color:var(--muted);text-transform:uppercase;white-space:nowrap}
.toolbar select{width:auto;min-width:180px;padding:7px 9px}
.toolbar .meta{margin:0 0 0 auto;text-align:right}
.checkedIntro{color:var(--muted);font-size:13.5px;padding:0 16px 6px;margin:0}
.checkedItem{border-top:1px solid var(--line);padding:10px 16px}
.checkedItem ul{margin:4px 0 0;padding-left:18px;color:#334155}
.checkedItem li{margin:2px 0}
.headerCard{display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap;background:#101826;border-radius:16px;padding:18px 20px;margin-bottom:12px}
.headerCard h1{color:#ffffff}
.headerCard .tagline{color:#9fb0c3;margin:5px 0 0}
.hcStats{display:flex;gap:10px;flex-wrap:wrap}
.stat{background:#1b2740;border:1px solid #2b3a5f;border-radius:12px;padding:9px 15px;text-align:center;min-width:98px}
.stat b{display:block;font-size:20px;color:#ffffff;line-height:1.2}
.stat span{font-size:10.5px;color:#9fb0c3;text-transform:uppercase;letter-spacing:.05em}
.warning{background:var(--orangebg);border:1px solid #fed7aa;color:#7c2d12;border-radius:12px;padding:10px 14px;margin:0 0 14px;font-size:14px}
.layout{display:grid;grid-template-columns:360px 1fr;gap:16px;align-items:start}
@media (max-width:900px){.layout{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;overflow:hidden}
.sideHead{display:flex;justify-content:space-between;align-items:center;padding:15px 16px 10px}
.sideHead h2,.detailHead h2{font-size:18px;margin:0}
.count{color:var(--muted);font-size:13px}
.seg{display:flex;gap:6px;padding:0 16px 13px}
.seg button{border:1px solid var(--line);background:#fff;border-radius:999px;padding:5px 11px;cursor:pointer;color:var(--muted);font-weight:600}
.seg button.on{background:var(--ink);color:#fff;border-color:var(--ink)}
.pathList{border-top:1px solid var(--line);max-height:760px;overflow:auto}
.pathItem{display:block;width:100%;text-align:left;border:0;border-bottom:1px solid var(--line);background:#fff;padding:13px 16px;cursor:pointer}
.pathItem:hover{background:#f8fafc}.pathItem.on{background:var(--redbg);box-shadow:inset 4px 0 0 var(--red)}
.badge{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.04em;border-radius:999px;padding:2px 8px;margin-bottom:5px}
.badge.tz{background:#fee2e2;color:var(--red)}.badge.ac{background:#ffedd5;color:var(--orange)}
.routeName{font-weight:700;font-size:14.5px;overflow-wrap:anywhere}
.pathMeta{color:var(--muted);font-size:12.5px;margin-top:3px}
.detail{padding:18px}
.detailHead{border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:6px}
.eyebrow{font-size:12px;font-weight:800;letter-spacing:.06em;color:var(--red);text-transform:uppercase}
.detailHead h2{font-size:23px;overflow-wrap:anywhere;margin:3px 0 8px}
.chips{display:flex;flex-wrap:wrap;gap:7px}
.chip{background:var(--chip);border-radius:999px;padding:3px 11px;font-size:12.5px;color:#334155}.chip b{color:var(--ink)}
.route{display:flex;flex-wrap:wrap;align-items:center;gap:7px;padding:14px 0 4px}
.node{background:#f8fafc;border:1.5px solid #94a3b8;border-radius:10px;padding:6px 10px;font-weight:700;font-size:13.5px;overflow-wrap:anywhere}
.node.start{border-color:var(--blue)}.node.end{border-color:var(--red);background:var(--redbg)}
.arrow{color:var(--muted);font-size:12px;font-weight:700;text-align:center}
.step{display:grid;grid-template-columns:42px 1fr;gap:13px;padding:17px 0;border-bottom:1px solid var(--line)}
.step:last-child{border-bottom:0}
.num{width:42px;height:42px;border-radius:50%;background:var(--red);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:17px}
.step h3{margin:1px 0 6px;font-size:18px}
.edgeLine{color:var(--muted);font-size:13px;margin-bottom:8px}.edgeLine b{color:var(--ink)}
.lbl{font-size:11.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase}
.ins{color:#243447}.ins .lbl{color:var(--blue)}
pre{background:var(--code);color:#e5edf7;border-radius:11px;padding:11px 13px;overflow-x:auto;font-size:13px;margin:8px 0}
.noCmd{background:#f8fafc;border:1px dashed var(--line);border-radius:11px;padding:10px 13px;color:var(--muted);margin:8px 0}
.after{background:var(--greenbg);border:1px solid #bbf7d0;border-radius:11px;padding:10px 13px;margin-top:9px}.after .lbl{color:var(--green)}
.final{margin-top:16px;background:var(--greenbg);border:1.5px solid var(--green);border-radius:14px;padding:15px 17px;font-size:16px}
.empty{padding:22px;color:var(--muted)}
.subCtl{margin-top:12px}
.modeSeg{display:flex;gap:6px;flex-wrap:wrap}
.modeSeg button{border:1px solid var(--line);background:#fff;border-radius:999px;padding:5px 11px;cursor:pointer;color:var(--muted);font-weight:600}
.modeSeg button.on{background:var(--ink);color:#fff;border-color:var(--ink)}
.checklist{background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;padding:12px 15px;margin:14px 0 2px}
.checklist ul{margin:6px 0 0;padding-left:18px}.checklist li{margin:3px 0}
.progressWrap{background:#e2e8f0;border-radius:999px;height:10px;margin:12px 0 4px;overflow:hidden}
.progressBar{background:var(--green);height:100%;width:0;transition:width .2s}
.pText{font-size:12.5px;color:var(--muted)}
.numbers{margin-top:10px;color:var(--muted);font-size:13px}
.numbers summary{cursor:pointer;font-weight:600}
.step.done .num{background:var(--green)}
.doneLbl{display:inline-flex;gap:7px;align-items:center;margin-top:10px;font-weight:700;color:var(--green);cursor:pointer}
footer{color:var(--muted);font-size:12.5px;margin-top:18px}
</style></head><body><div class="wrap">
<div class="headerCard">
  <div><h1>Auto<span>Hound</span> — Privilege Escalation Paths</h1>
  <p class="tagline">Pick a SharpHound dataset, pick a path, and follow the steps. This page shows escalation paths only — nothing else.</p></div>
  <div class="hcStats" id="hcStats"></div>
</div>
<div class="toolbar">
  <div class="toolItem"><label for="datasetSelect">Dataset</label><select id="datasetSelect"></select></div>
  <div class="toolItem"><label for="userSelect">I start from</label><select id="userSelect"></select></div>
  <div class="toolItem"><label>Reading level</label><div class="modeSeg" id="modeSeg"><button data-m="beginner" class="on">Beginner - plain words</button><button data-m="expert">Expert - technical names</button></div></div>
  <div class="meta" id="datasetMeta"></div>
</div>
<div id="warning"></div>
<main class="layout">
  <aside class="panel">
    <div class="sideHead"><h2>Escalation paths</h2><span class="count" id="pathCount"></span></div>
    <div class="seg" id="seg">
      <button data-f="all" class="on">All</button><button data-f="tier-zero">Tier-Zero</button><button data-f="admin-chain">Admin groups</button>
    </div>
    <div class="pathList" id="pathList"></div>
  </aside>
  <section class="panel detail" id="detail"></section>
</main>
<section class="panel" id="checkedPanel" style="margin-top:16px">
  <div class="sideHead"><h2>Checked — no full path</h2><span class="count" id="checkedCount"></span></div>
  <p class="checkedIntro">These accounts were checked too. They have some power, but in this data it does not reach Domain Admin or an admin group — the reason is written with each account, so nothing looks missing.</p>
  <div id="checkedList"></div>
</section>
<footer>AutoHound v1.4 · Fully offline · One dashboard for many collections: <b>python3 autohound.py --input a.zip --input b.zip --out reports</b> (multiple zip files are treated as separate datasets). Replace &lt;YOUR_USER&gt;, &lt;PASS&gt; and &lt;NEW_PASSWORD&gt; in commands with your own values. For authorized labs / pentests only.</footer>
</div>
<script>
const DATA = __DATA_JSON__;
const DATASETS = (DATA.datasets && DATA.datasets.length) ? DATA.datasets : [DATA];
function esc(s){ return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }
function shortName(x, domain){
  if(!x) return '';
  let v = String(x);
  if (v.indexOf('@') >= 0) v = v.split('@')[0];
  else if (domain && v.toUpperCase().endsWith('.' + String(domain).toUpperCase())) v = v.slice(0, -String(domain).length - 1);
  return v;
}
let dsIndex = 0, filter = 'all', selected = 0, mode = 'beginner', userFilter = 'all';
const doneState = {};
function ds(){ return DATASETS[dsIndex]; }
function typeMap(d){
  const m = {};
  (d.paths || []).forEach(p => (p.nodes || []).forEach(n => { m[n.name] = n.type; }));
  return m;
}
function pathScore(p){
  // Importance = how many accounts share the path, then target level,
  // then confidence. An already-admin 1-hop path scores lowest by construction.
  return Math.log2(1 + (p.shared_by || 1)) * 100 + (p.kind==='tier-zero' ? 25 : 10) + (p.confidence || 0) / 10 - p.length;
}
function sortedPaths(d){
  const arr = (d.paths || []).slice();
  arr.sort((a,b)=> pathScore(b) - pathScore(a));
  return arr;
}
function visiblePaths(){
  let all = sortedPaths(ds());
  if (filter !== 'all') all = all.filter(p => p.kind === filter);
  if (userFilter !== 'all') all = all.filter(p => shortName(p.start, ds().domain) === userFilter);
  return all;
}

// ---- plain-English wording for each permission type ----
function fill(t, st){ return t.split('{from}').join(st.from).split('{to}').join(st.to); }
const WHY = {
  MemberOf: 'Membership gives you every right of the group automatically. There is nothing to exploit in this step - if you are a member, the power is already yours when you log in.',
  GenericWrite: 'Being able to change an object also means being able to change the setting that controls it. On a group, that setting is the member list - so the attacker can add an account they control.',
  ForceChangePassword: 'This right exists so support staff can reset forgotten passwords. The old password is not required, and here the right also works on an admin account - that is the mistake.',
  AddMember: 'Group membership means group power. Adding a controlled account to a powerful group is direct privilege escalation.',
  AddSelf: 'Group membership means group power. Adding yourself to a powerful group is direct privilege escalation.',
  GenericAll: 'GenericAll is full control: on a group, add members; on a user, reset the password or add a shadow credential; on a domain, request every password hash.',
  WriteDacl: 'If you can change the permission list of an object, you can write your own name into it with Full Control, then take over.',
  WriteOwner: 'The owner of an object can always change its permission list. Become the owner, then give yourself Full Control.',
  Owns: 'The owner of an object can always change its permission list and give themselves Full Control.',
  AddKeyCredentialLink: 'A key credential works like an extra key for the account. Attaching one lets you prove you are that account without knowing or changing its password.',
  WriteSPN: 'Adding a service name (SPN) makes the account Kerberoastable: anyone can request its service ticket and attack the ticket offline.',
  AdminTo: 'This is lateral movement: you are the local administrator of that computer, so you control the machine and can look for credentials and live sessions on it.',
  HasSession: 'A logged-in user leaves credential material in the memory of that machine. Whoever controls the machine can recover it - but only after the machine is compromised.',
  CanRDP: 'RDP gives a desktop on the machine. It is not admin by itself, but it is a foothold for finding more rights and sessions.',
  CanPSRemote: 'PowerShell remoting gives a remote shell on the machine - another lateral-movement door.',
  GetChanges: 'This is only half of the DCSync rights. It works only together with GetChangesAll on the same domain.',
  GetChangesAll: 'Domain Controllers replicate password data to each other. With both replication rights, an account can ask a Domain Controller for every password hash (DCSync).',
  AllowedToDelegate: 'Delegation lets a service act for a user. With the wrong setting it can act for any user, including an administrator.',
  AllowedToAct: 'With resource-based delegation, a controlled account can be trusted to act for others on this computer - including acting as its administrator.',
  GPLink: 'A linked Group Policy runs on those computers as SYSTEM. Editing the policy makes the computers run your command as SYSTEM at the next refresh.'
};
const RESULT = {
  MemberOf: 'You now hold every right of {to}. Continue the next step as {to}.',
  GenericWrite: 'After the change, log out and back in so the new rights are in your token. You now act with the power of {to}.',
  ForceChangePassword: 'You can now log in as {to} with the new password. You are {to} for the next step.',
  AddMember: 'Log out and back in so the membership is in your token. You are now a member of {to}.',
  AddSelf: 'Log out and back in so the membership is in your token. You are now a member of {to}.',
  GenericAll: 'You have full control of {to}.',
  AdminTo: 'You have an administrator shell on {to}. Check who is logged in there and what credentials are available.',
  HasSession: 'Recover the credential of {to} from {from}, then authenticate as {to}.',
  GPLink: 'At the next Group Policy refresh, your command runs as SYSTEM on the target computers.'
};
function actionTitle(e, st, tt){
  const to = st.to, from = st.from;
  switch(e){
    case 'MemberOf': return 'Use your membership in ' + to;
    case 'GenericWrite': return tt==='Group' ? 'Add your account to the ' + to + ' group' : tt==='GPO' ? 'Take control of the ' + to + ' policy' : 'Take control of ' + to;
    case 'ForceChangePassword': return 'Reset the password of ' + to;
    case 'AddMember': case 'AddSelf': return 'Add your account to the ' + to + ' group';
    case 'GenericAll': return tt==='Domain' ? 'Use full control of the domain' : tt==='Group' ? 'Add your account to the ' + to + ' group (full control)' : 'Use full control of ' + to;
    case 'WriteDacl': case 'WriteOwner': case 'Owns': return 'Take control of ' + to + ' through its permissions';
    case 'AddKeyCredentialLink': return 'Plant a shadow credential on ' + to;
    case 'WriteSPN': return 'Make ' + to + ' Kerberoastable and crack its password';
    case 'AdminTo': return 'Log in to ' + to + ' as administrator';
    case 'HasSession': return 'Recover the session of ' + to + ' from ' + from;
    case 'CanRDP': return 'Open an RDP desktop on ' + to;
    case 'CanPSRemote': return 'Open a remote shell on ' + to;
    case 'GetChanges': case 'GetChangesAll': return 'Request the domain password hashes (DCSync)';
    case 'AllowedToDelegate': return 'Impersonate a powerful user to ' + to;
    case 'AllowedToAct': return 'Impersonate an administrator to ' + to;
    case 'GPLink': return 'Use the linked policy to run as SYSTEM on ' + to;
    default: return 'Use the ' + e + ' permission on ' + to;
  }
}

// ---- v1.2 helpers: plain phrases, hardest-step warnings, checklist ----
const PHRASE = {
  MemberOf: 'is a member of', GenericWrite: 'can change / edit', ForceChangePassword: 'can reset the password of',
  AddMember: 'can add members to', AddSelf: 'can add itself to', GenericAll: 'has FULL control of',
  WriteDacl: 'can rewrite the permissions of', WriteOwner: 'can take ownership of', Owns: 'owns',
  AddKeyCredentialLink: 'can plant a shadow credential on', WriteSPN: 'can set a service name (SPN) on',
  AdminTo: 'is the local administrator of', HasSession: 'holds the live session of', CanRDP: 'can RDP into',
  CanPSRemote: 'can remote-shell into', GetChanges: 'has half of the DCSync rights on', GetChangesAll: 'can DCSync the domain from',
  AllowedToDelegate: 'can impersonate users to', AllowedToAct: 'can impersonate an admin to', GPLink: 'applies by policy to'
};
const HARD = {
  HasSession: 'this step only works while that user is still logged in to the machine, and only after you control that machine.',
  WriteSPN: 'this step ends with cracking a password offline - a weak password cracks fast, a strong one may not crack at all.',
  GPLink: 'this step waits for the next Group Policy refresh (up to about 90 minutes) before your command runs.',
  GetChanges: 'GetChanges alone is not enough - it must be paired with GetChangesAll on the same domain.',
  CanRDP: 'RDP alone is not admin - it only gives you a foothold on the machine.',
  CanPSRemote: 'remoting alone is not admin - it only gives you a shell on the machine.'
};
const TOOL_RULES = [
  ['bloodyad', 'BloodyAD'], ['secretsdump', 'Impacket (secretsdump)'], ['getuserspns', 'Impacket (GetUserSPNs)'],
  ['getnpusers', 'Impacket (GetNPUsers)'], ['sharpgpoabuse', 'SharpGPOAbuse'], ['rubeus', 'Rubeus'],
  ['psexec', 'Impacket (psexec)'], ['wmiexec', 'Impacket (wmiexec)'], ['evil-winrm', 'Evil-WinRM'],
  ['hashcat', 'hashcat'], ['dacledit', 'Impacket (dacledit)'], ['owneredit', 'Impacket (owneredit)'],
  ['rbcd', 'Impacket (rbcd)'], ['getst', 'Impacket (getST)'], ['pywhisker', 'pyWhisker'], ['whisker', 'pyWhisker'],
  ['net group', 'Windows net commands'], ['net user', 'Windows net commands'], ['rpc', 'rpcclient / net rpc']
];
function toolsFromCommands(p){
  const blob = (p.steps || []).map(s => (s.commands || []).join(' ')).join(' ').toLowerCase();
  const out = [];
  TOOL_RULES.forEach(r => { if (blob.indexOf(r[0]) >= 0 && out.indexOf(r[1]) < 0) out.push(r[1]); });
  return out.length ? out : ['no special tool - a normal logon is enough'];
}
function buildChecklist(p, dom){
  let hard = null;
  (p.steps || []).forEach((s, i) => { if (!hard && HARD[s.edge]) hard = 'Step ' + (i + 1) + ': ' + HARD[s.edge]; });
  const items = [
    'Your starting point: the account <b>' + esc(shortName(p.start, dom)) + '</b> - or any account that is a member of it. Nothing else is needed to begin.',
    'Tools used in the commands below: <b>' + esc(toolsFromCommands(p).join(', ')) + '</b>.',
    hard ? ('Watch out - ' + esc(hard)) : 'No single hard step: every step in this path is a normal, reliable permission.'
  ];
  return '<div class="checklist"><div class="lbl" style="color:var(--blue)">Before you start - check these 3 things</div><ul>' +
    items.map(t => '<li>' + t + '</li>').join('') + '</ul></div>';
}
function renderUserOptions(){
  const d = ds();
  // All enabled user accounts + every path start (groups included), by short name.
  const names = new Set(d.users || []);
  (d.paths || []).forEach(p => names.add(shortName(p.start, d.domain)));
  const opts = Array.from(names).sort();
  const sel = document.getElementById('userSelect');
  sel.innerHTML = '<option value="all">All accounts - show every path</option>' +
    opts.map(s => '<option value="' + esc(s) + '">' + esc(s) + '</option>').join('');
  if (userFilter !== 'all' && opts.indexOf(userFilter) < 0) userFilter = 'all';
  sel.value = userFilter;
}
// ---- rendering ----
function renderOptions(){
  const sel = document.getElementById('datasetSelect');
  sel.innerHTML = DATASETS.map((d,i)=> '<option value="' + i + '">' + esc(d.label || d.domain || ('Dataset ' + (i+1))) + '</option>').join('');
  sel.value = String(dsIndex);
}
function renderMeta(){
  const d = ds();
  document.getElementById('datasetMeta').textContent =
    'Domain: ' + (d.domain || '-') + ' · ' + (d.stats ? d.stats.nodes : '-') + ' objects · ' +
    (d.verification_text || '').split(' verified against raw edges').join('');
  const q = d.data_quality || {};
  document.getElementById('warning').innerHTML = (q.session_edges === 0)
    ? '<div class="warning"><b>Session data is missing in this collection (0 sessions).</b> Paths that need a live admin session on a machine cannot appear here. Collect with SharpHound <b>-c All</b> for the full picture.</div>' : '';
}
function renderList(){
  const list = visiblePaths();
  if (selected >= list.length) selected = 0;
  document.getElementById('pathCount').textContent = list.length + ' shown';
  document.getElementById('pathList').innerHTML = list.length ? list.map((p,i)=>
    '<button class="pathItem' + (i===selected ? ' on' : '') + '" data-i="' + i + '">' +
    '<span class="badge ' + (p.kind==='tier-zero' ? 'tz' : 'ac') + '">' + (p.kind==='tier-zero' ? 'TIER-ZERO / DOMAIN ADMIN' : 'ADMIN GROUP') + '</span>' +
    '<div class="routeName">' + esc(shortName(p.start, ds().domain)) + ' → ' + esc(shortName(p.target, ds().domain)) + '</div>' +
    '<div class="pathMeta">' + (mode === 'expert' ? (p.length + ' steps · ' + Math.round(p.confidence || 0) + '% confidence' + ((p.shared_by||1) > 1 ? ' · shared by ' + p.shared_by + ' accounts' : '')) : (p.length + ' steps')) + '</div></button>'
  ).join('') : '<div class="empty">No paths in this view.</div>';
  document.querySelectorAll('.pathItem').forEach(b => b.addEventListener('click', ()=>{ selected = +b.dataset.i; renderList(); renderDetail(); }));
}
function renderDetail(){
  const d = ds(), list = visiblePaths(), box = document.getElementById('detail');
  const p = list[selected];
  if (!p){
    if (userFilter !== 'all') {
      const c = (d.checked || []).find(x => x.short === userFilter);
      box.innerHTML = '<div class="empty"><h3 style="margin:0 0 6px;color:var(--ink)">No path from ' + esc(userFilter) + ' in this data</h3>' +
        '<p>' + esc(userFilter) + ' was checked. In this collection, this account does not reach Domain Admin or an admin group.</p>' +
        (c ? '<p style="color:var(--ink)"><b>What this account does have:</b></p><ul>' + c.reasons.map(r => '<li>' + esc(r) + '</li>').join('') + '</ul>'
           : '<p>It holds no special permission in this data - only normal group memberships.</p>') +
        ((d.data_quality || {}).session_edges === 0 ? '<p>Note: this collection has 0 recorded sessions, so a path through a live session on a machine this account admins cannot be seen here.</p>' : '') + '</div>';
    } else {
      box.innerHTML = '<div class="empty">No privilege-escalation path matches this selection. Pick another account or filter.</div>';
    }
    return;
  }
  const tm = typeMap(d), dom = d.domain;
  const pkey = dsIndex + '|' + p.start + '|' + p.target;
  const doneCount = (p.steps || []).filter((_, i) => doneState[pkey + '|' + i]).length;
  let h = '<div class="detailHead"><div class="eyebrow">' + (p.kind === 'tier-zero' ? 'Path to Tier-Zero / Domain Admin' : 'Path to an admin group') + '</div>' +
    '<h2>' + esc(shortName(p.start, dom)) + ' → ' + esc(shortName(p.target, dom)) + '</h2>';
  if (mode === 'expert') {
    h += '<div class="chips"><span class="chip"><b>' + p.length + '</b>&nbsp;steps</span>' +
      '<span class="chip"><b>' + Math.round(p.confidence || 0) + '%</b>&nbsp;confidence</span>' +
      '<span class="chip">shared by&nbsp;<b>' + (p.shared_by || 1) + '</b>&nbsp;account(s)</span>' +
      (p.alt_paths != null ? '<span class="chip"><b>' + p.alt_paths + (p.alt_capped ? '+' : '') + '</b>&nbsp;alternative route(s)</span>' : '') +
      '<span class="chip">start as&nbsp;<b>' + esc(shortName(p.start, dom)) + '</b></span></div>';
  } else {
    h += '<div class="chips"><span class="chip">start as&nbsp;<b>' + esc(shortName(p.start, dom)) + '</b></span>' +
      '<span class="chip"><b>' + p.length + '</b>&nbsp;steps</span>' +
      '<span class="chip">ends as&nbsp;<b>' + esc(shortName(p.target, dom)) + '</b></span></div>';
  }
  h += '<details class="numbers"><summary>Numbers &amp; technical details</summary><div>' +
    'Confidence: ' + Math.round(p.confidence || 0) + '% · Shared by ' + (p.shared_by || 1) + ' account(s)' +
    (p.alt_paths != null ? ' · Alternative routes: ' + p.alt_paths + (p.alt_capped ? '+' : '') : '') +
    ' · Type: ' + esc(p.kind) + ' · Path check: ' + esc(d.verification_text || '-') + '</div></details>';
  h += '<div class="progressWrap"><div class="progressBar" id="pBar" style="width:' + Math.round(doneCount * 100 / Math.max(1, p.length)) + '%"></div></div>' +
    '<div class="pText" id="pText">' + doneCount + ' of ' + p.length + ' steps done - tick each step when you finish it</div></div>';
  h += buildChecklist(p, dom);
  // route strip
  h += '<div class="route">';
  (p.nodes || []).forEach((n, i) => {
    if (i > 0) { const e = (p.edges || [])[i - 1] || ''; h += '<span class="arrow">— ' + esc(mode === 'expert' ? e : (PHRASE[e] || e)) + ' →</span>'; }
    h += '<span class="node' + (i === 0 ? ' start' : (i === p.nodes.length - 1 ? ' end' : '')) + '">' + esc(n.short || shortName(n.name, dom)) + '</span>';
  });
  h += '</div>';
  // steps
  (p.steps || []).forEach((raw, i) => {
    const st = { from: shortName(raw.from, dom), to: shortName(raw.to, dom) };
    const tt = tm[raw.to] || 'Base';
    const why = WHY[raw.edge] || 'This permission is in the collected data, and the next step depends on it.';
    const after = RESULT[raw.edge] ? fill(RESULT[raw.edge], st) : 'You now reach ' + st.to + '. Continue with the next step as ' + st.to + '.';
    const cmds = raw.commands || [];
    const done = !!doneState[pkey + '|' + i];
    const edgeLine = (mode === 'expert')
      ? '<b>' + esc(st.from) + '</b> —[' + esc(raw.edge) + ']→ <b>' + esc(st.to) + '</b>'
      : '<b>' + esc(st.from) + '</b> ' + esc(PHRASE[raw.edge] || raw.edge) + ' <b>' + esc(st.to) + '</b>';
    h += '<div class="step' + (done ? ' done' : '') + '"><div class="num">' + (i + 1) + '</div><div>' +
      '<h3>' + esc(actionTitle(raw.edge, st, tt)) + '</h3>' +
      '<div class="edgeLine">' + edgeLine + (i === 0 ? ' · You start as ' + esc(st.from) : ' · You are now acting as ' + esc(st.from)) + '</div>' +
      '<p class="ins"><span class="lbl">Instruction&nbsp;&nbsp;</span>' + esc(raw.note || why) + '</p>' +
      '<p style="color:var(--muted);margin:6px 0"><span class="lbl" style="color:var(--orange)">Why it works&nbsp;&nbsp;</span>' + esc(why) + '</p>' +
      (cmds.length ? '<div><span class="lbl" style="color:var(--orange)">Run this</span><pre>' + esc(cmds.join('\n')) + '</pre></div>'
                   : '<div class="noCmd">No command needed for this step - the right is automatic when you log in.</div>') +
      '<div class="after"><span class="lbl">After this step&nbsp;&nbsp;</span>' + esc(after) + '</div>' +
      '<label class="doneLbl"><input type="checkbox" class="stepCheck" data-i="' + i + '"' + (done ? ' checked' : '') + '> Mark step ' + (i + 1) + ' as done</label>' +
      '</div></div>';
  });
  h += '<div class="final"><b>Result:</b> following these ' + p.length + ' steps, a user starting as <b>' + esc(shortName(p.start, dom)) + '</b> ends as <b>' + esc(shortName(p.target, dom)) + '</b>.' +
    (p.kind === 'tier-zero' ? ' That is Domain Admin level - the highest control in the domain.' : ' That target holds the admin-group rights shown in this path.') + '</div>';
  box.innerHTML = h;
  document.querySelectorAll('.stepCheck').forEach(cb => cb.addEventListener('change', () => {
    const i = +cb.dataset.i;
    doneState[pkey + '|' + i] = cb.checked;
    const card = cb.closest('.step'); if (card) card.classList.toggle('done', cb.checked);
    const c = (p.steps || []).filter((_, j) => doneState[pkey + '|' + j]).length;
    const bar = document.getElementById('pBar'), tx = document.getElementById('pText');
    if (bar) bar.style.width = Math.round(c * 100 / Math.max(1, p.length)) + '%';
    if (tx) tx.textContent = c + ' of ' + p.length + ' steps done - tick each step when you finish it';
  }));
}
function renderChecked(){
  const d = ds(), list = d.checked || [], panel = document.getElementById('checkedPanel');
  if (!list.length){ panel.style.display = 'none'; return; }
  panel.style.display = '';
  document.getElementById('checkedCount').textContent = list.length + ' account(s)';
  document.getElementById('checkedList').innerHTML = list.map(c =>
    '<div class="checkedItem"><b>' + esc(c.short || shortName(c.name, d.domain)) + '</b><ul>' +
    c.reasons.map(r => '<li>' + esc(r) + '</li>').join('') + '</ul></div>').join('');
}
function renderStats(){
  const d = ds();
  document.getElementById('hcStats').innerHTML =
    '<div class="stat"><b>' + (d.stats ? d.stats.nodes : '-') + '</b><span>Objects analysed</span></div>' +
    '<div class="stat"><b>' + (d.paths || []).length + '</b><span>Escalation paths</span></div>' +
    '<div class="stat"><b>' + (d.checked || []).length + '</b><span>Checked — no path</span></div>';
}
function renderAll(){ renderOptions(); renderMeta(); renderStats(); renderUserOptions(); renderList(); renderDetail(); renderChecked(); }
document.getElementById('datasetSelect').addEventListener('change', e=>{ dsIndex = +e.target.value; selected = 0; userFilter = 'all'; renderMeta(); renderStats(); renderUserOptions(); renderList(); renderDetail(); renderChecked(); });
document.getElementById('userSelect').addEventListener('change', e=>{ userFilter = e.target.value; selected = 0; renderList(); renderDetail(); });
document.querySelectorAll('#modeSeg button').forEach(b => b.addEventListener('click', ()=>{
  mode = b.dataset.m;
  document.querySelectorAll('#modeSeg button').forEach(x => x.classList.toggle('on', x===b));
  renderList(); renderDetail();
}));
document.querySelectorAll('#seg button').forEach(b => b.addEventListener('click', ()=>{
  filter = b.dataset.f; selected = 0;
  document.querySelectorAll('#seg button').forEach(x => x.classList.toggle('on', x===b));
  renderList(); renderDetail();
}));
renderAll();
</script></body></html>
"""


def render_dashboard(data, out_path):
    # Strip the heavy full-graph payload: the Path Explorer never uses it,
    # and dropping it keeps multi-dataset dashboards small and fast.
    def slim(d):
        if not isinstance(d, dict):
            return d
        return {k: v for k, v in d.items() if k != "fullgraph"}
    if isinstance(data, dict) and isinstance(data.get("datasets"), list):
        payload = {"datasets": [slim(d) for d in data["datasets"]]}
    else:
        payload = slim(data)
    html = TEMPLATE.replace("__DATA_JSON__", json.dumps(payload, ensure_ascii=False))
    Path(out_path).write_text(html, encoding="utf-8")
    return out_path
