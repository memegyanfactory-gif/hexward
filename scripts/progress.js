// Builds docs/progress.html from ROADMAP.md checkboxes and recent commits.
// Run after ticking boxes in ROADMAP.md:   node scripts/progress.js
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const root = path.join(__dirname, "..");
const md = fs.readFileSync(path.join(root, "ROADMAP.md"), "utf8");

// Parse "## Phase ..." sections, optional plain-text sub-groups, and "- [x]/[ ]" items.
const phases = [];
let cur = null;
let group = "";
for (const line of md.split(/\r?\n/)) {
  const h = line.match(/^## (Phase [^·]+)·\s*(.+)$/);
  if (h) {
    cur = { id: h[1].trim(), name: h[2].trim(), items: [] };
    phases.push(cur);
    group = "";
    continue;
  }
  if (line.startsWith("## ")) { cur = null; continue; }
  if (!cur) continue;
  const it = line.match(/^- \[( |x)\] (.+)$/);
  if (it) {
    cur.items.push({ done: it[1] === "x", text: it[2].replace(/`([^`]+)`/g, "$1").replace(/\*\*([^*]+)\*\*/g, "$1"), group });
  } else if (/^[A-Z][A-Za-z ]+$/.test(line.trim()) && line.trim().length < 40) {
    group = line.trim();
  }
}

let commits = [];
let head = "";
try {
  head = execSync("git rev-parse --short HEAD", { cwd: root }).toString().trim();
  commits = execSync('git log -8 --pretty=format:"%h\t%ad\t%s" --date=short', { cwd: root })
    .toString()
    .trim()
    .split("\n")
    .map((l) => { const [hash, date, ...s] = l.split("\t"); return { hash, date, subject: s.join("\t") }; });
} catch { /* not a git checkout */ }

const total = phases.reduce((n, p) => n + p.items.length, 0);
const done = phases.reduce((n, p) => n + p.items.filter((i) => i.done).length, 0);
const data = { phases, total, done, head, commits, generated: new Date().toISOString() };

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const blocks = (d, t, n = 20) => {
  const on = t ? Math.round((d / t) * n) : 0;
  return `<span class="blocks" role="img" aria-label="${d} of ${t} done">${Array.from({ length: n }, (_, i) => `<i class="${i < on ? "on" : ""}"></i>`).join("")}</span>`;
};
const pct = (d, t) => (t ? Math.round((d / t) * 100) : 0);

const phaseHtml = phases
  .map((p) => {
    const d = p.items.filter((i) => i.done).length;
    let lastGroup = null;
    const items = p.items
      .map((i) => {
        const g = i.group && i.group !== lastGroup ? `<li class="group">${esc(i.group)}</li>` : "";
        lastGroup = i.group;
        return `${g}<li class="${i.done ? "done" : "todo"}"><span class="box" aria-hidden="true"></span><span>${esc(i.text)}</span></li>`;
      })
      .join("");
    const state = d === p.items.length ? "complete" : d === 0 ? "next" : "active";
    return `<section class="phase ${state}">
  <header>
    <p class="eyebrow">${esc(p.id)}</p>
    <h2>${esc(p.name)}</h2>
    <div class="meta"><span class="chip ${state}">${state === "complete" ? "Done" : state === "active" ? "In progress" : "Not started"}</span><span class="num">${d} / ${p.items.length} · ${pct(d, p.items.length)}%</span></div>
    ${blocks(d, p.items.length)}
  </header>
  <ul>${items}</ul>
</section>`;
  })
  .join("\n");

const commitHtml = commits.map((c) => `<li><span class="hash">${esc(c.hash)}</span><span class="date">${esc(c.date)}</span><span>${esc(c.subject)}</span></li>`).join("");

const html = `<title>Hexward Progress</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400..700&family=Geist+Mono:wght@400..600&family=Pixelify+Sans:wght@500..700&display=swap">
<style>
:root{
  /* Layout: one column, pixel progress blocks, phase cards in a responsive grid */
  --bg:#0B0F14;--surface:#10161E;--raised:#161E28;--line:#263241;--fg:#E6EDF3;--fg2:#A3B1C2;--fg3:#7A8A9D;
  --moss:#4BE07A;--moss-dim:#17663F;--oxide:#F0743A;--signal:#5AA9FF;--shadow:#020406;
  --pixel:"Pixelify Sans",ui-monospace,monospace;--body:"Geist",system-ui,"Segoe UI",sans-serif;--mono:"Geist Mono",ui-monospace,Consolas,monospace;
  color-scheme:dark;
}
@media (prefers-color-scheme: light){:root:not([data-theme="dark"]){--bg:#F3F6F2;--surface:#FFFFFF;--raised:#E8EEE9;--line:#C9D4CC;--fg:#0B0F14;--fg2:#3F4B57;--fg3:#5F6B78;--moss:#1A7F45;--moss-dim:#BFE8CB;--oxide:#C9531B;--signal:#1C64C8;--shadow:#B9C6BD;color-scheme:light}}
:root[data-theme="light"]{--bg:#F3F6F2;--surface:#FFFFFF;--raised:#E8EEE9;--line:#C9D4CC;--fg:#0B0F14;--fg2:#3F4B57;--fg3:#5F6B78;--moss:#1A7F45;--moss-dim:#BFE8CB;--oxide:#C9531B;--signal:#1C64C8;--shadow:#B9C6BD;color-scheme:light}
:root[data-theme="dark"]{--bg:#0B0F14;--surface:#10161E;--raised:#161E28;--line:#263241;--fg:#E6EDF3;--fg2:#A3B1C2;--fg3:#7A8A9D;--moss:#4BE07A;--moss-dim:#17663F;--oxide:#F0743A;--signal:#5AA9FF;--shadow:#020406;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 var(--body)}
.wrap{max-width:1120px;margin:0 auto;padding-block:40px 64px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));display:flex;flex-direction:column;gap:32px}
.eyebrow{font:500 11px/1.4 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--fg3);margin:0}
h1{font:700 clamp(32px,6vw,52px)/1.05 var(--pixel);margin:6px 0 0;text-wrap:balance}
h2{font:600 22px/1.2 var(--pixel);margin:4px 0 0;text-wrap:balance}
.hero{display:flex;flex-direction:column;gap:14px}
.big{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
.big .pct{font:700 clamp(48px,10vw,88px)/1 var(--pixel);color:var(--moss);font-variant-numeric:tabular-nums}
.big .of{font:500 15px var(--mono);color:var(--fg2)}
.blocks{display:grid;grid-template-columns:repeat(20,minmax(0,1fr));gap:4px;width:100%}
.blocks i{height:14px;background:var(--raised)}
.blocks i.on{background:var(--moss)}
.hero .blocks i{height:22px}
.panel{background:var(--surface);box-shadow:0 -2px 0 var(--line),0 2px 0 var(--line),-2px 0 0 var(--line),2px 0 0 var(--line);margin:2px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:22px}
@media (max-width:760px){.grid{grid-template-columns:minmax(0,1fr)}}
.phase{display:flex;flex-direction:column;background:var(--surface);box-shadow:0 -2px 0 var(--line),0 2px 0 var(--line),-2px 0 0 var(--line),2px 0 0 var(--line);margin:2px;min-width:0}
.phase.active{box-shadow:0 -2px 0 var(--moss),0 2px 0 var(--moss),-2px 0 0 var(--moss),2px 0 0 var(--moss),6px 6px 0 0 var(--shadow)}
.phase header{padding:18px 18px 14px;display:flex;flex-direction:column;gap:8px;border-bottom:2px solid var(--line)}
.meta{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
.num{font:500 13px var(--mono);color:var(--fg2);font-variant-numeric:tabular-nums}
.chip{font:500 11px/1 var(--mono);letter-spacing:.06em;text-transform:uppercase;padding:5px 8px;display:inline-flex;gap:6px;align-items:center}
.chip::before{content:"";width:6px;height:6px;background:currentColor}
.chip.complete{color:var(--moss);background:color-mix(in srgb,var(--moss) 14%,transparent)}
.chip.active{color:var(--signal);background:color-mix(in srgb,var(--signal) 14%,transparent)}
.chip.next{color:var(--fg3);background:color-mix(in srgb,var(--fg3) 14%,transparent)}
ul{list-style:none;margin:0;padding:12px 18px 18px;display:flex;flex-direction:column;gap:7px}
li{display:grid;grid-template-columns:16px minmax(0,1fr);gap:10px;align-items:start;font-size:14px;color:var(--fg2)}
li.done{color:var(--fg)}
li.group{display:block;font:500 11px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--fg3);padding-top:6px}
.box{width:14px;height:14px;margin-top:3px;box-shadow:inset 0 0 0 2px var(--line)}
li.done .box{background:var(--moss);box-shadow:none}
.commits{padding:16px 18px}
.commits ul{padding:0}
.commits li{grid-template-columns:auto auto minmax(0,1fr);gap:12px;font-size:13px;color:var(--fg)}
.hash{font:500 12px var(--mono);color:var(--oxide)}
.date{font:12px var(--mono);color:var(--fg3)}
.foot{font:12px var(--mono);color:var(--fg3)}
.foot a{color:var(--moss)}
</style>
<div class="wrap">
  <section class="hero">
    <p class="eyebrow">Hexward · build progress</p>
    <h1>Every byte, warded.</h1>
    <div class="big"><span class="pct">${pct(done, total)}%</span><span class="of">${done} of ${total} roadmap items done across ${phases.length} phases</span></div>
    ${blocks(done, total)}
    <p class="foot">Generated from ROADMAP.md at commit <b>${esc(head || "local")}</b> · ${esc(new Date().toUTCString())} · <a href="https://github.com/memegyanfactory-gif/hexward">github.com/memegyanfactory-gif/hexward</a></p>
  </section>
  <div class="grid">
${phaseHtml}
  </div>
  <section class="panel commits">
    <p class="eyebrow">Latest work</p>
    <ul>${commitHtml}</ul>
  </section>
</div>
<script type="application/json" id="progress-data">${JSON.stringify(data).replace(/</g, "\\u003c")}</script>
`;

fs.mkdirSync(path.join(root, "docs"), { recursive: true });
fs.writeFileSync(path.join(root, "docs", "progress.html"), html);
console.log(`progress: ${done}/${total} (${pct(done, total)}%) across ${phases.length} phases -> docs/progress.html`);
