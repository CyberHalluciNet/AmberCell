# AmberCell website design — ASCII terminal style

**Status:** Landing implemented in [`site/index.html`](../site/index.html); extra
pages (`cells.html`, …) still proposed below.
**Stack:** Classic static HTML + CSS + one CDN script — no build step, no framework
**Controls:** [ascii.rest](https://github.com/bas3line/ascii) animated ASCII web components
**Audience:** General public *and* cybersecurity professionals — both, on every page
**Host:** GitHub Pages via [`.github/workflows/pages.yml`](../.github/workflows/pages.yml)
→ <https://cyberhallucinet.github.io/AmberCell/>

---

## 1. Concept — "Caught in amber"

AmberCell's name is the design: insects trapped in amber, perfectly preserved for
millions of years. Attackers poke at real-looking services and every packet,
credential, and payload is preserved — sealed in amber.

Everything follows from three words: **terminal, amber, sealed.**

- **Terminal** — the whole site lives inside a warm monospace 72ch column that
  reads like a well-behaved TTY, not a hacked-together console theme.
- **Amber** — one brand color (amber `#ffb000` on near-black `#0e0b07`), plus
  exactly two semantic colors (green pass / red alert). Nothing else.
- **Sealed** — sections are literally framed (ASCII box-drawing borders), the
  containment story is visualized everywhere, and the motion is calm —
  `prefers-reduced-motion` users get static frames automatically (built into
  the library).

Tagline candidates:

```
Real daemons. Real attackers. Sealed in amber.
A single-host honeypot that runs real services, records everything, and never fights back.
Watch the break-in. Keep the evidence. Lose nothing.
```

---

## 2. Design tokens

```css
:root {
  --bg:        #0e0b07;   /* warm near-black            */
  --bg-raised: #151009;   /* boxed sections             */
  --amber:     #ffb000;   /* brand — CRT amber          */
  --amber-dim: #b87d10;   /* borders, secondary chrome  */
  --text:      #e8dcc8;   /* warm off-white body text   */
  --muted:     #8a7d6a;   /* captions, meta             */
  --ok:        #3fbf6f;   /* kill-bar pass, "up" states */
  --alert:     #e0533d;   /* alerts, "down"/beta states */
  --font-mono: ui-monospace, "SF Mono", "JetBrains Mono", "Cascadia Mono",
               Menlo, Consolas, monospace;
}
body {
  font: 400 15px/1.75 var(--font-mono);
  background: var(--bg);
  color: var(--text);
  max-width: 74ch;
  margin: 0 auto;
  padding: 0 1.25rem;
}
```

Rules of restraint:

- Monochrome amber + green/red semantics only. No gradients, no blue links
  (links are amber, underline on hover).
- One animated piece per viewport, max ~6 per page. Art is seasoning, not soup.
- Every decorative `<ascii-art>` gets `aria-hidden` or a meaningful `label`;
  all core content is plain HTML that works with zero JavaScript.

---

## 3. Site map

```text
index.html           landing: what/why/how, dual-lane story, cells wall, safety, CTA
cells.html           full catalog: 28 protocol cells × 8 waves, providers, ports
architecture.html    the professional page: topology, evidence pipeline, kill bars
quickstart.html      30-second lab start + production checklist + remote sensors
404.html             "not found" — with the library's own piece
assets/site.css      ~200 lines, no framework
assets/site.js       ~40 lines: nav highlight, copy-to-clipboard buttons
```

No bundler, no framework, no analytics beyond a privacy-friendly counter if any.
Deployable as GitHub Pages from `/site/` (or `docs/`).

---

## 4. Page wireframes

### 4.1 `index.html`

```text
┌──────────────────────────────────────────────────────────────────────┐
│  ● ambercell                                    cells · docs · github │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ██████╗██╗  ██╗                                                     │
│   ...big-text AMBERCELL...        ┌ boot log (animated) ──────────┐  │
│                                  │ [  OK  ] amberctl init          │  │
│   A single-host honeypot that    │ [  OK  ] ambernet 172.30.0.0/16 │  │
│   runs REAL daemons, records     │ [ LISTEN] ftp  telnet smtp pop3 │  │
│   every packet, and never        │ [  OK  ] evidence /var/ambercell│  │
│   fights back.                   │ ▂▂▂ heartbeat (live pulse) ▂▂▂ │  │
│                                                                      │
│   [ > quickstart_ ]   [ > architecture_ ]   [ > cells________ ]      │
│                                                                      │
├─ typewriter line ────────────────────────────────────────────────────┤
│ > 28 protocols. 8 waves. real daemons only. zero mocks.*             │
│   *except orchestration traps — by design, and we'll tell you why    │
├──────────────────────────────────────────────────────────────────────┤
│ ┌ IN PLAIN TERMS ────────────────────────────────┐ ┌ FOR OPERATORS ─┐│
│ │ A decoy computer that LOOKS like a real        │ │ Single-host     ││
│ │ mail server, file server, database...          │ │ Docker Compose  ││
│ │ Attackers poke at it. Every move is recorded   │ │ honeypot; real  ││
│ │ — like insects preserved in amber.             │ │ daemons, netns  ││
│ │ Nothing of YOURS is ever exposed.              │ │ collectors, nft ││
│ └────────────────────────────────────────────────┘ └────────────────┘│
├─ the cells wall (excerpt; full table on cells.html) ──────────────────┤
│  CORE        smtp·25   pop3·110   ftp·21  telnet·23                   │
│  WAVE A–E    ssh  redis  mqtt  http  mysql  postgres  smb  mongo ...  │
│  WAVE F–H    dns·53  tftp·69  snmp·161  ntp·123  syslog·514  sip·5060│
│              ldap·389  imap·143  memcached·11211  rdp·3389  vnc·5900  │
│              netbios·137                                               │
├─ how it works: 3 framed steps ────────────────────────────────────────┤
│  [1] DECOY     real OSS daemons behind nftables DNAT                  │
│  [2] RECORD    collectors capture pcap + flows + creds, append-only   │
│  [3] EXAMINE   one-way dead drop; SIEM pulls, never touches the pot   │
├─ safety strip (green) ────────────────────────────────────────────────┤
│  [✓] lab default   [✓] no host orchestration   [✓] egress allowlist   │
├──────────────────────────────────────────────────────────────────────┤
│  ready in ~30 seconds on a laptop  →  [ > run_the_lab_demo_ ]         │
│                                     ─ progress bar piece (fills) ─    │
├─ footer: divider piece · github · license · a small owl watches ──────┤
└──────────────────────────────────────────────────────────────────────┘
```

**Dual-audience device (site-wide):** every concept appears twice in boxed
lanes — `IN PLAIN TERMS` (analogy, zero jargon) and `FOR OPERATORS`
(accurate, terse). The box-frame aesthetic makes the two-lane layout feel
native, not bolted on.

Plain-language analogies to reuse:

| Real thing | Plain terms |
| --- | --- |
| Honeypot | a decoy mailbox that looks real and records everyone who opens it |
| Dead drop | a one-way letterbox: intelligence goes out, nobody comes in |
| Containment / kill bars | a sealed glass case with 14 trip-wires |
| Collector | a security camera that also films in the dark (pcap) |
| Provider pluggability | the decoy can wear different costumes (postfix↔exim) |

### 4.2 `cells.html`

```text
│ CELLS — the decoy catalog                                              │
│ every cell is a REAL open-source daemon. no fake shells, ever.         │
├─ file tree piece (decorative nav) ──┬─ the real table (HTML) ─────────┤
│  ambercell/                         │ CELL     DAEMON      PORTS      │
│  ├─ core/        smtp pop3 ftp ...  │ smtp     postfix      25/tcp    │
│  ├─ wave-a/      ssh redis mqtt     │ dns      coredns      53 udp+tcp│
│  ├─ ...          (links to rows)    │ rdp      xrdp         3389/tcp  │
│  └─ wave-h/      imap rdp vnc       │ vnc      Xvnc (open)  5900/tcp  │
│                                     │ ...24 more rows, grouped by wave│
│  wave legend: ▓ core ▓ a–e ▓ f ▓ g ▓ h   filters: ALL / REAL / TRAP   │
│  [i] beta cells (ntp·syslog·ldap) carry a dim amber marker + tooltip  │
└───────────────────────────────────────────────────────────────────────┘
```

Per-cell detail rows expand (pure `<details>`): daemon + alternates, ports,
what attackers typically try, what gets captured. This is the page
professionals bookmark.

### 4.3 `architecture.html`

```text
│ ARCHITECTURE — how the sealing works                                   │
├─ topology diagram: hand-drawn ASCII (static <pre>, not a piece) ──────┤
│   internet ──▶ nftables DNAT ──▶ ambernet (icc=off) ──▶ cells         │
│                     │                     └─▶ *-collector ──▶ /var/.. │
│                     ▼                                                │
│               egress allowlist ─▶ dns sinkhole                       │
├─ evidence pipeline: 4 stacked frames ─────────────────────────────────┤
│  raw pcap ─▶ normalized JSONL ─▶ ATT&CK/Engage enrichment ─▶ AI (off  │
│  path, bounded, deterministic critic)                                 │
├─ KILL BARS — the 14 trip-wires ───────────────────────────────────────┤
│  G1 unexplained egress        [✓]      G8 no real orchestration   [✓] │
│  G2 no lateral reach          [✓]      G13 no amplification (dns/     │
│  ...                                     memcached ~1x answers)   [✓] │
├─ data pieces row (illustrative, labelled as such) ────────────────────┤
│  [ sparkline ]  [ gauge ]  [ heatmap ]   ← "what fleet telemetry      │
│                                            looks like in the dead     │
│                                            drop bulletin"             │
├─ dead drop: one-way letterbox diagram + age encryption note ──────────┤
└────────────────────────────────────────────────────────────────────────┘
```

### 4.4 `quickstart.html`

```text
│ QUICKSTART — sealed in ~30 seconds                                     │
│ [1] clone        $ git clone .../AmberCell && cd AmberCell             │
│ [2] build        $ cd amberctl && go build -o amberctl . && cd ..      │
│ [3] run          $ amberctl init --yes && amberctl up ftp              │
│ [4] watch        $ amberctl drill ftp && amberctl status               │
│     every $ line has a [copy] button — zero typing required           │
│  ── terminal piece shows the REAL expected output, animated ──         │
│  ── then: production checklist (nft, apparmor, sinkhole, G1–G14) ──    │
│  ── then: remote sensors (link DEADDROP.md guide) ──                   │
└────────────────────────────────────────────────────────────────────────┘
```

### 4.5 `404.html`

The library's `not-found` piece, one line of copy ("this packet never
arrived — everything else did"), and a link home. The classic.

---

## 5. ascii.rest component map

| Location | Piece | Notes |
| --- | --- | --- |
| Hero, right column | `boot-log` | the product IS a boot sequence; instantly signals "real daemons" |
| Hero wordmark | `big-text` | AMBERCELL as ASCII block letters; `mono` for one-ink |
| Hero, small | `heartbeat` | "evidence pulse" under the boot log |
| Section transitions | `dividers` | between major sections, `aria-hidden` |
| Landing teaser line | `typewriter` | types the "28 protocols..." line once, then static |
| Quickstart demo | `terminal` | real amberctl transcript |
| Quickstart CTA | `progress-bar` | fills on scroll into view |
| Cells nav (decor) | `file-tree` | doubles as wave navigation |
| Cells table rows | — | plain HTML `<table>`; tables are for reading |
| Architecture telemetry row | `sparkline` + `gauge` + `heatmap` | clearly captioned "illustrative" |
| Loading between page jumps (opt) | `spinners` | only if we add view transitions |
| Support matrix | `debian`, `ubuntu` | distro logos for the host matrix |
| amberctl section | `go` logo; `python` for collectors | brand-accurate |
| Beta cells (ntp/syslog/ldap) | `skeleton` | "still forming" — cute, honest |
| 404 | `not-found` | the library's own |
| Footer easter egg | `owl` | the owl watches (aria-hidden) |
| Avoid | `matrix-rain` everywhere, `glitch` on body text | cliché + unreadable |

Budget: ≤6 animated pieces per page, `fps` default, every piece gets
`label` (or `aria-hidden` when decorative). Reduced-motion = static first
frame — free from the library, keep it.

---

## 6. Static implementation notes

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AmberCell — real-daemon honeypot, sealed in amber</title>
  <meta name="description" content="Single-host honeypot running real
        open-source daemons behind nftables containment...">
  <link rel="stylesheet" href="assets/site.css">
  <!-- favicon: https://ascii.rest/svg/donut.dark.svg (or a custom amber hex) -->
</head>
<body>
  <script type="module" src="https://ascii.rest/ascii.js"></script>
  <ascii-art piece="boot-log" label="Boot sequence of AmberCell services"></ascii-art>
  ...
</body>
</html>
```

- One CDN `<script type="module">`; if it fails to load the site is still
  fully readable (art is enhancement, content is plain HTML).
- `<pre>`-based ASCII diagrams (topology) are static text — selectable,
  accessible, zero runtime.
- `site.js` does exactly two things: active-nav highlight and copy buttons
  on code lines.
- Mobile: the 74ch column and `font-size: 13px` under 640px; hero art
  hides below 480px (art, not content).
- Print stylesheet: amber → black, art hidden.
- GitHub Pages: content lives in `/site/`; deploy with the `pages` Actions
  workflow (branch “folder” source cannot select `/site`).

---

## 7. Copy bank (grounded, no vaporware)

Only claim what exists today: 28 cells / 8 waves, real daemons, collector
pcap+JSONL evidence, nftables containment, kill bars G1–G14, dead drop
(summary class today, bulletin + age encryption flagged as *shipping next*
until merged), amberctl in Go, lab/production profiles, pluggable providers
with digest pins. Beta cells labeled beta. Traps labeled traps.
```
