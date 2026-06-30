/* Gullwing HUD — front-end logic (vanilla JS, no framework).
   State + render + SVG gauge + rAF count-up, wired to the Python bridge via
   pywebview.api.*. Falls back to a local mock so the page also opens standalone
   in a browser for visual checks. */
"use strict";

/* ── small DOM helpers ─────────────────────────────────────────────────────*/
const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => { const n = document.createElement(tag);
  if (cls) n.className = cls; if (html != null) n.innerHTML = html; return n; };
const NS = "http://www.w3.org/2000/svg";
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const REDUCE = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ── icons (inline SVG) ────────────────────────────────────────────────────*/
const ICON = {
  search:'<svg viewBox="0 0 18 18" width="16" height="16"><circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12.5 12.5 16 16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  shield:'<svg viewBox="0 0 18 18" width="16" height="16"><path d="M9 1.5 15 4v5c0 4-2.6 6.4-6 7.5C5.6 15.4 3 13 3 9V4Z" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>',
  bolt:'<svg viewBox="0 0 18 18" width="16" height="16"><path d="M10 1 3.5 10H8l-1 7 6.5-9H9Z" fill="currentColor"/></svg>',
  trash:'<svg viewBox="0 0 18 18" width="16" height="16"><path d="M3 5h12M7 5V3h4v2M5 5l1 11h6l1-11" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
  bars:'<svg viewBox="0 0 18 18" width="16" height="16"><path d="M3 15V8M8 15V3M13 15v-5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>',
  chip:'<svg viewBox="0 0 18 18" width="16" height="16"><rect x="5" y="5" width="8" height="8" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M7 2v3M11 2v3M7 13v3M11 13v3M2 7h3M2 11h3M13 7h3M13 11h3" stroke="currentColor" stroke-width="1.4"/></svg>',
};

/* ── modules ───────────────────────────────────────────────────────────────*/
const MODULES = [
  { id:"home",  num:"01", title:"SYSTEM OVERVIEW",     desc:"Every subsystem, scored and monitored in real time.",
    nav:"OVERVIEW",    primary:"RUN DIAGNOSTIC", ico:"search", feed:"ANOMALY FEED",          feedsub:"All subsystems · one-click reversible fixes" },
  { id:"perf",  num:"02", title:"PERFORMANCE TUNING",  desc:"latency · power · throughput",
    nav:"PERFORMANCE", primary:"SCAN PERFORMANCE", ico:"bolt", feed:"PERFORMANCE FINDINGS", feedsub:"tuning opportunities" },
  { id:"sec",   num:"03", title:"SECURITY AUDIT",       desc:"exposure & hardening review",
    nav:"SECURITY",    primary:"SCAN SECURITY", ico:"shield", feed:"SECURITY FINDINGS",     feedsub:"flagged for review" },
  { id:"clean", num:"04", title:"DISK CLEANER",         desc:"reclaimable space & debris",
    nav:"CLEANER",     primary:"CLEAN NOW", ico:"trash", feed:"RECLAIMABLE ITEMS",          feedsub:"tap to select" },
  { id:"bench", num:"05", title:"BENCHMARK",            desc:"CPU · memory · storage tiers",
    nav:"BENCHMARK",   primary:"RUN BENCHMARK", ico:"bars", feed:"BENCHMARK RESULTS",       feedsub:"hardware tiers" },
  { id:"oc",    num:"06", title:"OVERCLOCK ADVISOR",    desc:"headroom — advisory only",
    nav:"OVERCLOCK",   primary:"COPY OC PROFILE", ico:"chip", feed:"ADVISORY",              feedsub:"never auto-applied" },
];
const MOD = Object.fromEntries(MODULES.map(m => [m.id, m]));
const SEV_VAR = { CRITICAL:"--crit", HIGH:"--high", MEDIUM:"--med", REVIEW:"--review", INFO:"--info" };
const GRADE_BANDS = [["S",92,"#5BF5E4"],["A",82,"#7CFFB0"],["B",70,"#FFB23E"],
                     ["C",55,"#FFD23E"],["D",40,"#FF8A3D"],["F",0,"#FF4D5E"]];
const gradeLetter = (s) => (GRADE_BANDS.find(b => s >= b[1]) || GRADE_BANDS[5]);

const TICKER = "SECURE OFFLINE LINK ESTABLISHED /// 0 OUTBOUND CONNECTIONS /// SNAPSHOT VAULT READY /// 6 MODULES ONLINE /// NO TELEMETRY · NO ACCOUNT · NO CLOUD /// EVERY ACTION SHOWS ITS COMMAND /// ";

/* ── state ─────────────────────────────────────────────────────────────────*/
const S = {
  active:"home", scanning:false, version:"—",
  scans:{}, bench:null, oc:null,
  live:{}, fixed:new Set(), cleanSel:new Set(),
  shown:0, raf:0, reduce:REDUCE,
};

/* ── bridge ────────────────────────────────────────────────────────────────*/
let USE_MOCK = false;   // set true only when no pywebview bridge ever appears
const api = (method, ...args) => {
  if (!USE_MOCK && window.pywebview && window.pywebview.api && window.pywebview.api[method])
    return Promise.resolve(window.pywebview.api[method](...args));
  return Promise.resolve(Mock[method] ? Mock[method](...args) : null);
};
/* Wait for pywebview to inject its api before making real calls. Resolves false
   (→ use the in-page Mock) only when run in a plain browser with no bridge. */
function apiReady(){
  return new Promise((res) => {
    if (window.pywebview && window.pywebview.api) return res(true);
    let done = false;
    const ok = () => { if (!done){ done = true; res(true); } };
    window.addEventListener("pywebviewready", ok, { once:true });
    setTimeout(() => { if (!done){ done = true; USE_MOCK = !(window.pywebview && window.pywebview.api);
      res(!USE_MOCK); } }, 1600);
  });
}

/* ── JARVIS / toast ────────────────────────────────────────────────────────*/
function jarvis(t){ $("jarvisText").textContent = t; }
let toastT = 0;
function toast(t){ const n = $("toast"); n.textContent = t; n.classList.add("show");
  clearTimeout(toastT); toastT = setTimeout(() => n.classList.remove("show"), 2600); }

/* ── waveform + clock + ticker ─────────────────────────────────────────────*/
function buildWave(){ const w = $("wave"); w.innerHTML = "";
  for (let i = 0; i < 26; i++){ const b = el("i");
    const h = 5 + (Math.sin(i*1.7)*0.5+0.5)*16;
    b.style.height = h.toFixed(1)+"px";
    b.style.animationDuration = (0.7+((i*7)%9)/10).toFixed(2)+"s";
    b.style.animationDelay = ((i*53)%900/1000).toFixed(2)+"s";
    w.appendChild(b); } }
function tickClock(){ const d = new Date();
  $("clock").textContent = d.toTimeString().slice(0,8); }
function buildTicker(){ const t = $("tickerTrack");
  t.innerHTML = `<span>${TICKER}</span><span>${TICKER}</span>`; }

/* ── SVG gauge ─────────────────────────────────────────────────────────────*/
const GC = 220, GR = 148, GCIRC = 2*Math.PI*GR;
function buildGauge(value, color){
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 440 440");
  for (let i = 0; i < 72; i++){
    const a = (i/72)*Math.PI*2 - Math.PI/2, major = i % 6 === 0, r1 = GR + (major?10:5);
    const ln = document.createElementNS(NS, "line");
    ln.setAttribute("x1", GC+Math.cos(a)*GR); ln.setAttribute("y1", GC+Math.sin(a)*GR);
    ln.setAttribute("x2", GC+Math.cos(a)*r1); ln.setAttribute("y2", GC+Math.sin(a)*r1);
    ln.setAttribute("stroke", major ? "rgba(255,255,255,.32)" : "rgba(255,255,255,.13)");
    ln.setAttribute("stroke-width", major ? 1.6 : 1);
    svg.appendChild(ln);
  }
  const track = document.createElementNS(NS, "circle");
  track.setAttribute("cx", GC); track.setAttribute("cy", GC); track.setAttribute("r", GR);
  track.setAttribute("fill", "none"); track.setAttribute("stroke", "rgba(255,255,255,.06)");
  track.setAttribute("stroke-width", 7); svg.appendChild(track);
  const arc = document.createElementNS(NS, "circle");
  arc.id = "gaugeArc";
  arc.setAttribute("cx", GC); arc.setAttribute("cy", GC); arc.setAttribute("r", GR);
  arc.setAttribute("fill", "none"); arc.setAttribute("stroke-width", 7);
  arc.setAttribute("stroke-linecap", "round");
  arc.setAttribute("stroke-dasharray", GCIRC);
  arc.setAttribute("transform", `rotate(-90 ${GC} ${GC})`);
  svg.appendChild(arc);
  const dot = document.createElementNS(NS, "circle");
  dot.id = "gaugeDot"; dot.setAttribute("r", 5); svg.appendChild(dot);
  $("gaugeWrap").innerHTML = ""; $("gaugeWrap").appendChild(svg);
  setGauge(value, color);
}
function setGauge(value, color){
  const arc = $("gaugeArc"), dot = $("gaugeDot"); if (!arc) return;
  const frac = clamp(value, 0, 100)/100;
  arc.setAttribute("stroke", color);
  arc.setAttribute("stroke-dashoffset", GCIRC*(1-frac));
  arc.style.filter = `drop-shadow(0 0 12px ${color})`;
  const ea = frac*Math.PI*2 - Math.PI/2;
  dot.setAttribute("cx", GC+Math.cos(ea)*GR); dot.setAttribute("cy", GC+Math.sin(ea)*GR);
  dot.setAttribute("fill", color); dot.style.filter = `drop-shadow(0 0 8px ${color})`;
}

/* ── core readout ──────────────────────────────────────────────────────────*/
function renderCore(){
  const m = S.active, r = $("readout");
  let top = "GULLWING", color = "var(--cy)", bigHTML = "—", sub = "", tag = "";
  let gaugeVal = 0;

  if (m === "home" || m === "perf" || m === "sec"){
    const sc = S.scans[m];
    const liveScore = sc ? scoreNow(m) : 0;
    color = sc ? gradeLetter(liveScore)[2] : "var(--cy)";
    gaugeVal = liveScore;
    if (m === "home"){
      top = S.scanning ? "ANALYZING" : "GULLWING";
      bigHTML = `<span data-grade style="color:${color}">${sc ? gradeLetter(liveScore)[0] : "—"}</span>`;
      sub = `<span data-score>${liveScore}</span> / 100`;
      tag = "SYSTEM INTEGRITY";
    } else {
      top = S.scanning ? "ANALYZING" : (m === "perf" ? "PERFORMANCE" : "SECURITY");
      bigHTML = `<span data-score style="color:${color}">${sc ? liveScore : "—"}</span>`;
      sub = "/ 100";
      tag = m === "perf" ? "PERFORMANCE SCORE" : "SECURITY SCORE";
    }
  } else if (m === "clean"){
    const gb = cleanSelectedGB(), tot = cleanTotalGB();
    color = "var(--gold)"; gaugeVal = tot ? (gb/tot)*100 : 0;
    top = "RECLAIMABLE"; bigHTML = `<span data-score style="color:var(--gold)">${gb.toFixed(1)}</span><span class="u">GB</span>`;
    sub = "READY TO RECLAIM"; tag = "DISK CLEANER";
  } else if (m === "bench"){
    const b = S.bench; color = "var(--cy2)"; gaugeVal = b && b.index != null ? b.index : 0;
    top = S.scanning ? "RUNNING…" : "BENCHMARK";
    bigHTML = `<span data-score style="color:var(--cy2)">${b && b.index != null ? b.index : "—"}</span>`;
    sub = b && b.index != null ? "PERFORMANCE INDEX" : "PRESS RUN"; tag = "HARDWARE INDEX";
  } else if (m === "oc"){
    const o = S.oc; color = "var(--gold)"; gaugeVal = o && o.headroom ? parseInt(o.headroom,10)||0 : 0;
    top = "HEADROOM";
    bigHTML = `<span style="color:var(--gold)">${o && o.headroom ? o.headroom : "—"}</span>`;
    sub = "ESTIMATED HEADROOM"; tag = "OVERCLOCK ADVISOR";
  }

  r.innerHTML = `<div class="readout-top">${top}</div>
    <div class="readout-big">${bigHTML}</div>
    <div class="readout-sub">${sub}</div>
    <div class="readout-tag">${tag}</div>`;
  const cssColor = color.startsWith("var(") ? getComputedStyle(document.documentElement)
    .getPropertyValue(color.slice(4,-1)).trim() || "#35C5FF" : color;
  buildGauge(S.scanning && (m==="home"||m==="perf"||m==="sec"||m==="bench") ? 0 : gaugeVal, cssColor);
  S.shown = gaugeVal;
}

/* count-up: animate gauge + the [data-score] number together (no CSS transition) */
function animateCore(to, color){
  const r = $("readout"); const elScore = r.querySelector("[data-score]");
  const grade = r.querySelector("[data-grade]");
  const cssColor = typeof color === "string" ? color : "#35C5FF";
  if (S.reduce){ if (elScore) elScore.textContent = fmtScore(to);
    if (grade) grade.textContent = gradeLetter(to)[0]; setGauge(to, cssColor); S.shown = to; return; }
  cancelAnimationFrame(S.raf);
  const from = S.shown || 0, dur = 1000, t0 = performance.now();
  const step = (now) => {
    const k = Math.min(1, (now-t0)/dur), e = 1-Math.pow(1-k, 3);
    const v = from + (to-from)*e; S.shown = v;
    if (elScore) elScore.textContent = fmtScore(v);
    if (grade){ const g = gradeLetter(v); grade.textContent = g[0]; grade.style.color = g[2]; }
    setGauge(v, S.active==="home" ? gradeLetter(v)[2] : cssColor);
    if (k < 1) S.raf = requestAnimationFrame(step);
  };
  S.raf = requestAnimationFrame(step);
}
function fmtScore(v){ return S.active === "clean" ? (Math.round(v*10)/10).toFixed(1) : String(Math.round(v)); }

/* ── score helpers (mirror _compute_score: fixed findings stop deducting) ───*/
function scoreNow(m){ const sc = S.scans[m]; if (!sc) return 0;
  let regained = 0;
  for (const f of sc.findings) if (f.fixable && S.fixed.has(f.id)) regained += f.points;
  return clamp(sc.score + regained, 0, 100); }
function openCount(m){ const sc = S.scans[m]; if (!sc) return 0;
  return sc.findings.filter(f => f.fixable && !S.fixed.has(f.id)).length; }
function cleanTotalGB(){ const sc = S.scans.clean; if (!sc) return 0;
  return sc.findings.reduce((a,f) => a + (f._gb||0), 0); }
function cleanSelectedGB(){ const sc = S.scans.clean; if (!sc) return 0;
  return sc.findings.filter(f => S.cleanSel.has(f.id) && !S.fixed.has(f.id))
    .reduce((a,f) => a + (f._gb||0), 0); }

/* ── chips ─────────────────────────────────────────────────────────────────*/
function renderChips(){
  const c = $("chips"); c.innerHTML = ""; const m = S.active;
  const add = (label, val, gold) => { const ch = el("div", "chip"+(gold?" gold":""),
    `${label}<b>${val}</b>`); c.appendChild(ch); };
  const addSev = (label, sevVar, val) => { const ch = el("div", "chip",
    `<span class="chip-dot" style="background:var(${sevVar})"></span>${label}<b>${val}</b>`);
    c.appendChild(ch); };
  if (m === "home" || m === "perf" || m === "sec"){
    const sc = S.scans[m] || {counts:{}};
    addSev("HIGH", "--high", sc.counts.HIGH||0); addSev("MEDIUM", "--med", sc.counts.MEDIUM||0);
    addSev("REVIEW", "--review", sc.counts.REVIEW||0); addSev("INFO", "--info", sc.counts.INFO||0);
  } else if (m === "clean"){
    const n = [...S.cleanSel].filter(id => !S.fixed.has(id)).length;
    add("SELECTED", n, true); add("RECLAIM", cleanSelectedGB().toFixed(1)+" GB", true);
  } else if (m === "bench"){
    const b = S.bench || {}; add("CPU", b.cpu??"—"); add("GPU", b.gpu??"n/a");
    add("MEM", b.mem??"—"); add("DISK", b.disk??"—");
  } else if (m === "oc"){
    const o = S.oc || {}; add("ADVISORY", (o.cards||[]).length, true);
    add("AUTO-APPLY", "NEVER", true);
  }
}

/* ── feed (right panel) per module ─────────────────────────────────────────*/
function renderFeed(){
  const f = $("feed"); f.innerHTML = ""; const m = S.active;
  if (m === "home" || m === "perf" || m === "sec") return renderFindings(f, m);
  if (m === "clean") return renderCleaner(f);
  if (m === "bench") return renderBench(f);
  if (m === "oc")    return renderOC(f);
}

function renderFindings(f, m){
  const sc = S.scans[m];
  if (!sc){ f.appendChild(el("div","feed-intro","Press the action button to run this scan.")); return; }
  if (!sc.findings.length){ f.appendChild(el("div","feed-intro","No findings — this area is clean.")); return; }
  const order = {CRITICAL:0,HIGH:1,MEDIUM:2,REVIEW:3,INFO:4};
  [...sc.findings].sort((a,b)=>order[a.sev]-order[b.sev]).forEach((fd,i) => {
    const card = buildCard(fd); card.style.animationDelay = (i*0.04)+"s"; f.appendChild(card);
  });
}

function buildCard(fd){
  const fixed = S.fixed.has(fd.id);
  const card = el("div", "card"+(fixed?" fixed":""));
  card.style.setProperty("--sev", `var(${SEV_VAR[fd.sev]||"--info"})`);
  const top = el("div","card-top");
  top.appendChild(el("span","sevchip",fd.sev));
  if (fixed) top.appendChild(el("span","fixedchip","✓ NEUTRALIZED · SNAPSHOT SAVED"));
  card.appendChild(top);
  card.appendChild(el("div","card-title",esc(fd.title)));
  if (fd.desc) card.appendChild(el("div","card-desc",esc(fd.desc)));
  if (fd.command) card.appendChild(el("div","cmd",`<span class="d">$</span>${esc(fd.command)}`));
  if (!fd.fixable){
    card.appendChild(el("div","advisory-note","ADVISORY ONLY · NO AUTO-FIX"));
  } else if (!fixed){
    const act = el("div","card-actions");
    const fix = el("button","btn btn-fix","NEUTRALIZE"); fix.onclick = () => onFix([fd.id]);
    const copy = el("button","btn btn-ghost","COPY"); copy.onclick = () => copyCmd(fd);
    act.appendChild(fix); act.appendChild(copy); card.appendChild(act);
    if (fd.revertable === false) card.appendChild(el("div","norev","⚠ CANNOT BE UNDONE"));
  } else {
    card.appendChild(el("div","advisory-note","RESTORE VIA · REVERT SESSION"));
  }
  return card;
}

function renderCleaner(f){
  const sc = S.scans.clean;
  f.appendChild(el("div","feed-intro",
    "Select items to reclaim space. Cleaning deletes files and cannot be undone."));
  if (!sc || !sc.findings.length){ f.appendChild(el("div","feed-intro","Nothing reclaimable found.")); return; }
  sc.findings.forEach((fd,i) => {
    const cleaned = S.fixed.has(fd.id), sel = S.cleanSel.has(fd.id);
    const row = el("div","junk"+(cleaned?" cleaned":sel?" sel":""));
    row.style.animationDelay = (i*0.04)+"s";
    row.appendChild(el("div","cbx", cleaned ? "" : (sel?"✓":"")));
    const body = el("div","junk-body");
    body.appendChild(el("div","junk-label",esc(fd.title)));
    body.appendChild(el("div","junk-note", cleaned ? "CLEARED" : esc(fd.fix||fd.desc||"")));
    row.appendChild(body);
    row.appendChild(el("div","junk-size", (fd._gb||0).toFixed(1)+" GB"));
    if (!cleaned) row.onclick = () => { sel ? S.cleanSel.delete(fd.id) : S.cleanSel.add(fd.id);
      render(); };
    f.appendChild(row);
  });
}

function renderBench(f){
  const b = S.bench;
  if (!b){ f.appendChild(el("div","feed-intro","Press RUN BENCHMARK to measure CPU, memory and storage.")); return; }
  (b.cards||[]).forEach((c,i) => {
    const card = el("div","resultcard"); card.style.animationDelay = (i*0.05)+"s";
    const top = el("div","resultcard-top");
    top.appendChild(el("div","resultcard-name",esc(c.name)));
    top.appendChild(el("div","resultcard-score", c.score!=null
      ? `${c.score}<span class="max">/100</span>` : `<span class="max">n/a</span>`));
    card.appendChild(top);
    const meter = el("div","meter-line"); meter.appendChild(el("i"));
    meter.querySelector("i").style.width = (c.score||0)+"%";
    card.appendChild(meter);
    if (c.note) card.appendChild(el("div","resultcard-note",esc(c.note)));
    f.appendChild(card);
  });
  f.appendChild(el("div","feed-intro",
    "Synthetic micro-benchmarks; indicative, not a substitute for full suites. GPU not benchmarked."));
}

function renderOC(f){
  const o = S.oc;
  f.appendChild(el("div","feed-warn",
    "Advisory only — Gullwing never changes your clocks. Apply these yourself in BIOS / UEFI."));
  if (!o || !o.cards.length){ f.appendChild(el("div","feed-intro","No overclock advisories for this hardware.")); return; }
  o.cards.forEach((c,i) => {
    const card = el("div","resultcard"); card.style.animationDelay = (i*0.05)+"s";
    card.appendChild(el("div","resultcard-name",esc(c.title)));
    if (c.desc) card.appendChild(el("div","resultcard-note",esc(c.desc)));
    if (c.fix) card.appendChild(el("div","resultcard-note","→ "+esc(c.fix)));
    f.appendChild(card);
  });
}

/* ── tallies + revert button ───────────────────────────────────────────────*/
function renderTallies(){
  $("tallyOpen").textContent = ["home","perf","sec"].includes(S.active) ? openCount(S.active)
    : (S.active==="clean" ? [...S.cleanSel].filter(id=>!S.fixed.has(id)).length : 0);
  $("tallyFixed").textContent = S.fixed.size;
}
function refreshRevert(can){ $("revertBtn").disabled = !can; }

/* ── header / nav / stepper ────────────────────────────────────────────────*/
function renderHeader(){
  const m = MOD[S.active], idx = MODULES.findIndex(x => x.id === S.active);
  $("pageNum").textContent = m.num; $("counterNum").textContent = m.num;
  // re-trigger gw-swap on the titles
  const t = $("screenTitles"); t.style.animation = "none"; void t.offsetWidth;
  t.style.animation = "";
  $("pageTitle").textContent = m.title; $("pageDesc").textContent = m.desc;
  $("panelTitle").textContent = m.feed; $("panelSub").textContent = m.feedsub;
  $("primaryLabel").textContent = m.primary; $("primaryIco").innerHTML = ICON[m.ico]||"";
  // stepper dots
  const st = $("stepper"); st.innerHTML = "";
  MODULES.forEach(mm => { const d = el("div","dot"+(mm.id===S.active?" on":""));
    d.title = mm.title; d.onclick = () => switchModule(mm.id); st.appendChild(d); });
  // nav
  const nav = $("nav"); nav.innerHTML = "";
  MODULES.forEach(mm => { const b = el("button","navbtn"+(mm.id===S.active?" on":""), mm.nav);
    b.onclick = () => switchModule(mm.id); nav.appendChild(b); });
}

/* ── panel count ───────────────────────────────────────────────────────────*/
function renderPanelCount(){
  const m = S.active; let n = 0, suffix = "";
  if (["home","perf","sec"].includes(m)){ n = (S.scans[m]?.findings.length)||0; suffix = " ACTIVE"; }
  else if (m === "clean") n = (S.scans.clean?.findings.length)||0;
  else if (m === "bench") n = (S.bench?.cards.length)||0;
  else if (m === "oc")    n = (S.oc?.cards.length)||0;
  $("panelCount").textContent = n + suffix;
}

/* ── full render of the dynamic regions ────────────────────────────────────*/
function render(){ renderHeader(); renderCore(); renderChips(); renderFeed();
  renderPanelCount(); renderTallies(); }

/* ── actions ───────────────────────────────────────────────────────────────*/
function setBusy(b){ S.scanning = b; $("stage").classList.toggle("busy", b);
  $("primaryBtn").disabled = b; }

async function runScan(m){
  setBusy(true); jarvis(`Scanning ${MOD[m].nav.toLowerCase()}…`); renderCore();
  const res = await api("scan", m); S.scans[m] = res;
  setBusy(false);
  render();
  animateCore(scoreNow(m), gradeLetter(scoreNow(m))[2]);
  const open = openCount(m);
  jarvis(m === "home"
    ? `Sweep complete. ${res.findings.length} signals — ${open} need your attention.`
    : `${MOD[m].nav} scan complete — ${open} actionable.`);
}

async function runBenchmark(){
  setBusy(true); S.bench = null; renderCore(); jarvis("Running hardware benchmark…");
  const res = await api("benchmark"); S.bench = res;
  setBusy(false); render();
  if (res.index != null) animateCore(res.index, "#8BFFF4");
  jarvis(res.index != null ? `Benchmark complete — index ${res.index}.` : "Benchmark complete.");
}

async function loadOC(){
  jarvis("Compiling overclock advisory…");
  S.oc = await api("overclock"); render();
  jarvis(S.oc.headroom ? `Estimated headroom ${S.oc.headroom} — advisory only.`
    : "Overclock advisory ready — advisory only.");
}

async function onPrimary(){
  const m = S.active;
  if (m === "home" || m === "perf" || m === "sec") return runScan(m);
  if (m === "bench") return runBenchmark();
  if (m === "clean") return doClean();
  if (m === "oc") return copyOCProfile();
}

async function onFix(ids){
  const info = await api("confirm_fix", ids);
  showConfirm(info, async () => {
    closeModal();
    jarvis("Applying fix — you may be asked to authorise…");
    const res = await api("apply_fix", ids);
    if (!res || !res.ok){
      if (res && res.denied){ showDenied(res.preview); return; }
      toast((res && res.reason) ? res.reason : "Fix failed."); jarvis("Fix did not complete.");
      return;
    }
    res.fixed.forEach(id => S.fixed.add(id));
    refreshRevert(res.can_revert);
    render();
    animateCore(scoreNow(S.active), gradeLetter(scoreNow(S.active))[2]);
    toast(`Neutralised ${res.fixed.length} — snapshot saved.`);
    jarvis("Done. Snapshot saved — fully reversible via Revert Session.");
  });
}

async function doClean(){
  const ids = [...S.cleanSel].filter(id => !S.fixed.has(id));
  if (!ids.length){ toast("Select at least one item to clean."); return; }
  const info = await api("confirm_fix", ids);
  showConfirm(info, async () => {
    closeModal(); jarvis("Reclaiming space…");
    const res = await api("clean", ids);
    if (!res || !res.ok){ if (res && res.denied){ showDenied(res.preview); return; }
      toast((res && res.reason)||"Clean failed."); return; }
    res.fixed.forEach(id => S.fixed.add(id));
    render(); toast(`Reclaimed ${res.reclaimed_gb} GB.`);
    jarvis(`Reclaimed ${res.reclaimed_gb} GB of disk space.`);
  }, true);
}

async function copyOCProfile(){
  const o = S.oc; if (!o || !o.cards.length){ toast("No advisory to copy."); return; }
  const txt = "Gullwing Overclock Advisory (apply manually in BIOS/UEFI)\n" +
    o.cards.map(c => `• ${c.title}${c.fix?` — ${c.fix}`:""}`).join("\n");
  await copyText(txt); toast("OC profile copied to clipboard.");
  jarvis("Overclock profile copied — apply it yourself in BIOS.");
}

async function onRevert(){
  jarvis("Reverting session…");
  const res = await api("revert_session");
  if (!res || !res.ok){ toast((res && res.reason)||"Revert reported issues."); }
  S.fixed.clear(); refreshRevert(false);
  // refresh current finding module so cards reappear as open
  if (["home","perf","sec"].includes(S.active)) await runScan(S.active); else render();
  toast("Session reverted — all fixes undone.");
  jarvis("Session reverted. Every change has been rolled back.");
}

function copyCmd(fd){ copyText((fd.commands||[fd.command]).join("\n")); toast("Command copied."); }
async function copyText(t){ try{ await navigator.clipboard.writeText(t); }
  catch(e){ await api("copy_text", t); } }

/* ── modal ─────────────────────────────────────────────────────────────────*/
function showConfirm(info, onApply, cleaning){
  const cmds = (info.commands||[]).map(c =>
    `<span class="d">$</span> ${esc(c)}`).join("\n") || "(no command)";
  const sudo = (!info.is_root && info.elevation);
  const flag = cleaning
    ? `<div class="modal-flag warn">⚠ Cleaning deletes files and cannot be undone.</div>`
    : (info.revertable
      ? `<div class="modal-flag ok">✓ Reversible — a snapshot is saved before applying.</div>`
      : `<div class="modal-flag warn">⚠ Cannot be undone: ${esc((info.non_revertable||[]).join(", "))}</div>`);
  const back = el("div","modal-back");
  back.innerHTML = `<div class="modal">
    <div class="modal-title">${cleaning?"CONFIRM CLEAN":"CONFIRM FIX"}</div>
    <div class="modal-sub">${info.count} action(s) will run${sudo?" with administrator privileges":""}.
      These exact commands execute:</div>
    <div class="modal-cmds">${cmds}</div>
    ${flag}
    <div class="modal-actions">
      <button class="btn btn-ghost" id="mCancel">CANCEL</button>
      <button class="btn btn-fix" id="mApply">${cleaning?"CLEAN":"APPLY"}</button>
    </div></div>`;
  $("modalMount").appendChild(back);
  back.querySelector("#mCancel").onclick = closeModal;
  back.querySelector("#mApply").onclick = onApply;
  back.onclick = (e) => { if (e.target === back) closeModal(); };
}
function showDenied(preview){
  const back = el("div","modal-back");
  back.innerHTML = `<div class="modal">
    <div class="modal-title">ADMINISTRATOR REQUIRED</div>
    <div class="modal-sub">Gullwing can't elevate on this system. Run these commands yourself:</div>
    <div class="modal-cmds">${esc(preview||"")}</div>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="mCopy">COPY COMMANDS</button>
      <button class="btn btn-fix" id="mClose">CLOSE</button>
    </div></div>`;
  $("modalMount").appendChild(back);
  back.querySelector("#mCopy").onclick = () => { copyText(preview||""); toast("Commands copied."); };
  back.querySelector("#mClose").onclick = closeModal;
  back.onclick = (e) => { if (e.target === back) closeModal(); };
}
function closeModal(){ $("modalMount").innerHTML = ""; }

/* ── module switch ─────────────────────────────────────────────────────────*/
function switchModule(id){
  if (id === S.active) return;
  S.active = id; closeModal(); render();
  const m = MOD[id];
  jarvis(`${m.title} — ${m.desc}.`);
  // auto-load advisory/benchmark-free modules lazily
  if (id === "oc" && !S.oc) loadOC();
  if (["home","perf","sec"].includes(id) && S.scans[id])
    animateCore(scoreNow(id), gradeLetter(scoreNow(id))[2]);
}

/* ── live sensors ──────────────────────────────────────────────────────────*/
const SENSORS = [
  { key:"cpu",  label:"CPU LOAD", unit:"%",  fmt:v=>Math.round(v),
    sub:v=>v>82?["HEAVY",true]:["NOMINAL",false], pct:v=>v },
  { key:"temp", label:"CPU TEMP", unit:"°C", fmt:v=>Math.round(v),
    sub:v=>v>70?["WARM",true]:["NOMINAL",false], pct:v=>clamp((v-30)/60*100,0,100) },
  { key:"ram",  label:"MEMORY",   unit:"GB", fmt:(v,d)=>`${v}`,
    sub:(v,d)=>[`/ ${d.ram_total||"—"} GB`,false], pct:(v,d)=>d.ram_total?v/d.ram_total*100:0, gold:true },
  { key:"disk", label:"STORAGE",  unit:"%",  fmt:v=>Math.round(v),
    sub:(v,d)=>[`${d.disk_free??"—"} GB FREE`,false], pct:v=>v },
  { key:"net",  label:"NETWORK",  unit:"KB/s", fmt:v=>Math.round(v),
    sub:(v,d)=>[d.vpn?"VPN UP":"NO VPN",false], pct:v=>clamp(v/500*100,0,100) },
];
function buildSensors(){
  const host = $("sensors"); host.innerHTML = "";
  SENSORS.forEach(s => {
    const tile = el("div","tile"); tile.dataset.k = s.key;
    tile.innerHTML = `<div class="tile-top"><span class="tile-label">${s.label}</span>
        <span class="tile-state"></span></div>
      <div class="tile-val"><span class="v">—</span><span class="unit">${s.unit}</span></div>
      <div class="meter">${'<i class="seg"></i>'.repeat(22)}</div>`;
    host.appendChild(tile);
  });
}
function paintSensors(){
  const d = S.live;
  SENSORS.forEach(s => {
    const tile = document.querySelector(`.tile[data-k="${s.key}"]`); if (!tile) return;
    const v = d[s.key];
    tile.querySelector(".v").textContent = (v==null) ? "—" : s.fmt(v, d);
    const [stext, warn] = (v==null) ? ["—",false] : s.sub(v, d);
    const st = tile.querySelector(".tile-state"); st.textContent = stext;
    st.classList.toggle("warn", !!warn);
    const lit = (v==null) ? 0 : Math.round(clamp(s.pct(v, d),0,100)/100*22);
    tile.querySelectorAll(".seg").forEach((seg,i) => {
      seg.classList.toggle("lit", i < lit); seg.classList.toggle("gold", !!s.gold); });
  });
}
async function pollSensors(){
  try{ S.live = await api("live_sensors") || {}; paintSensors(); }catch(e){}
  setTimeout(pollSensors, 1100);
}

/* ── boot sequence ─────────────────────────────────────────────────────────*/
const BOOT_LINES = ["MOUNTING LOCAL MODULES","ESTABLISHING OFFLINE SECURE LINK",
  "CALIBRATING SENSOR ARRAY","✓ GULLWING CORE ONLINE"];
function runBoot(done){
  if (S.reduce){ $("boot").classList.add("hide"); done(); return; }
  const host = $("bootLines");
  BOOT_LINES.forEach((line,i) => setTimeout(() => {
    const d = el("div", i===BOOT_LINES.length-1?"done":"", line); host.appendChild(d);
  }, 300 + i*340));
  setTimeout(() => { $("boot").classList.add("hide"); done(); }, 1900);
}

/* ── scaling (1440×900 → fit) ──────────────────────────────────────────────*/
function fit(){ const sc = Math.min(window.innerWidth/1440, window.innerHeight/900);
  $("canvas").style.transform = `scale(${sc})`; }

/* ── util ──────────────────────────────────────────────────────────────────*/
function esc(s){ return String(s==null?"":s).replace(/[&<>"]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

/* ── init ──────────────────────────────────────────────────────────────────*/
async function init(){
  buildWave(); buildTicker(); buildSensors(); tickClock();
  setInterval(tickClock, 1000);
  fit(); window.addEventListener("resize", fit);
  $("primaryBtn").onclick = onPrimary;
  $("revertBtn").onclick = onRevert;
  if (S.reduce){ $("ovScan").style.display="none"; }

  // Wait for the Python bridge before any real call, so we never silently run
  // on Mock data in the packaged app.
  await apiReady();

  const info = await api("app_info");
  if (info){ S.version = info.version; $("brandSub").textContent = `SECURITY CORE · v${info.version}`; }
  pollSensors();

  // crash recovery: offer to roll back an interrupted session
  const inc = await api("incomplete_sessions");
  if (inc && inc.length){
    jarvis(`An interrupted session was found (${inc[0].label}).`);
    offerRecovery(inc[0]);
  }

  render();
  runBoot(() => { jarvis("Gullwing core online. Running first diagnostic…"); runScan("home"); });
}

function offerRecovery(sess){
  const back = el("div","modal-back");
  back.innerHTML = `<div class="modal">
    <div class="modal-title">RESUME / REVERT SESSION</div>
    <div class="modal-sub">A previous fix session ("${esc(sess.label)}") didn't finish cleanly.
      Roll it back to the pre-fix snapshot?</div>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="rDismiss">DISMISS</button>
      <button class="btn btn-fix" id="rRevert">REVERT NOW</button>
    </div></div>`;
  $("modalMount").appendChild(back);
  back.querySelector("#rDismiss").onclick = () => { api("dismiss_session", sess.ts); closeModal(); };
  back.querySelector("#rRevert").onclick = async () => { closeModal();
    const r = await api("recover_session", sess.ts);
    toast(r && r.ok ? "Previous session reverted." : "Revert reported issues."); };
}

window.addEventListener("DOMContentLoaded", init);

/* ── mock (browser fallback for visual testing without pywebview) ───────────*/
const Mock = (() => {
  const rnd = (a,b) => a + Math.random()*(b-a);
  let liveBase = { cpu:24, temp:54, ram:11.2, ram_total:32, disk:61, disk_free:421, net:12, vpn:false };
  const F = (sev,title,desc,cmd,pts,rev=true) => ({ id:title.replace(/\W/g,"").slice(0,12),
    sev, title, desc, fix:"see command", command:cmd, commands:cmd?[cmd]:[], points:pts,
    revertable:rev, fixable:!!cmd, fixed:false });
  const SEED = {
    sec:[ F("HIGH","No active firewall","All open ports are directly reachable.","ufw enable",10),
          F("HIGH","SSH password auth enabled","Password login invites brute-forcing.","sed -i 's/.../' /etc/ssh/sshd_config",10),
          F("MEDIUM","Kernel ASLR not maximal","Lower ASLR weakens exploit mitigation.","sysctl -w kernel.randomize_va_space=2",3,false),
          F("REVIEW","SUID binary: /usr/bin/pkexec","Verify this is intentional.","",0),
          F("INFO","Secure Boot disabled","BIOS-level setting.","",0) ],
    perf:[ F("REVIEW","CPU governor: powersave","Switch to performance for max clocks.","cpupower frequency-set -g performance",1,false),
           F("REVIEW","Swappiness is 60","Lower it to favour RAM.","sysctl -w vm.swappiness=10",1),
           F("INFO","Transparent Huge Pages: madvise","Informational.","",0) ],
    clean:[ {...F("MEDIUM","Temporary files","User temp cache","rm -rf /tmp/*",3,false), _gb:2.4},
            {...F("REVIEW","Package cache","apt archives","apt clean",1,false), _gb:1.8},
            {...F("REVIEW","Browser caches","Chromium/Firefox","",1,false), _gb:1.1},
            {...F("INFO","Crash dumps & logs","old journals","",0), _gb:0.6} ],
  };
  const score = (fs) => clamp(100 - fs.filter(f=>f.fixable).reduce((a,f)=>a+f.points,0),0,100);
  const counts = (fs) => { const c={CRITICAL:0,HIGH:0,MEDIUM:0,REVIEW:0,INFO:0};
    fs.forEach(f=>c[f.sev]++); return c; };
  const grade = (s) => GRADE_BANDS.find(b=>s>=b[1])||GRADE_BANDS[5];
  const fixedSet = new Set();
  return {
    app_info:()=>({version:"2.0.0-mock",os:"Linux",is_root:false,elevation:true,incomplete_sessions:0}),
    live_sensors:()=>{ liveBase.cpu=clamp(liveBase.cpu+rnd(-12,12),5,95);
      liveBase.temp=clamp(liveBase.temp+rnd(-2,2),42,80); liveBase.net=clamp(liveBase.net+rnd(-8,12),0,300);
      liveBase.ram=clamp(liveBase.ram+rnd(-.6,.6),6,30);
      return {...liveBase, cpu:Math.round(liveBase.cpu), temp:Math.round(liveBase.temp),
        ram:Math.round(liveBase.ram*10)/10, net:Math.round(liveBase.net)}; },
    scan:(m)=>{ const fs = (m==="home") ? [...SEED.sec,...SEED.perf]
        : (SEED[m]||[]); const s=score(fs), g=grade(s);
      return {module:m, score:s, grade:g[0], gradeColor:g[2],
        findings:fs.map(f=>({...f})), counts:counts(fs)}; },
    confirm_fix:(ids)=>{ const all=[...SEED.sec,...SEED.perf,...SEED.clean];
      const sel=all.filter(f=>ids.includes(f.id));
      return {count:sel.length, commands:sel.map(f=>"sudo "+f.command),
        revertable:sel.every(f=>f.revertable!==false),
        non_revertable:sel.filter(f=>f.revertable===false).map(f=>f.title),
        is_root:false, elevation:true}; },
    apply_fix:(ids)=>{ ids.forEach(i=>fixedSet.add(i));
      return {ok:true, results:ids.map(i=>({cmd:i,rc:0,ok:true,out:""})), fixed:ids, can_revert:true}; },
    clean:(ids)=>({ok:true,results:[],fixed:ids,reclaimed_gb:Math.round(ids.length*1.4*10)/10}),
    revert_session:()=>({ok:true,results:[{action:"restore sshd_config",ok:true,detail:""}]}),
    benchmark:()=>({cpu:88,gpu:null,mem:98,disk:62,index:83,cards:[
      {name:"PROCESSOR",score:88,tier:"A",note:"Strong single-thread throughput."},
      {name:"MEMORY",score:98,tier:"S",note:"Excellent bandwidth."},
      {name:"STORAGE",score:62,tier:"C",note:"SATA-class sequential speed."} ]}),
    overclock:()=>({headroom:"+8%",advisory:true,cards:[
      {sev:"REVIEW",title:"CPU headroom +8%",desc:"Thermals allow a modest all-core bump.",fix:"Raise multiplier in BIOS"},
      {sev:"REVIEW",title:"Memory: enable XMP/EXPO",desc:"RAM is running below rated speed.",fix:"Enable XMP profile"} ]}),
    incomplete_sessions:()=>[],
    copy_text:()=>({ok:true}),
  };
})();
