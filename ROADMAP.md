<h1 align="center">GOSINT Roadmap</h1>

<p align="center">
  <b>From a working recon CLI into a composable, observable OSINT engine.</b><br>
  Every scan is a first-class run you can see through end to end; every capability is a
  small primitive that composes; detection is data-defined, not hardcoded.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/plan-leverage_ordered-F5A524">
  <img src="https://img.shields.io/badge/default-passive_first-34D399">
  <img src="https://img.shields.io/badge/north_star-observable_·_composable-3D9BFF">
</p>

---

**How to read this.** §1 is the shipped substrate — keep it, don't rebuild. §2 is the
forward plan as leverage-ordered milestones (M1–M7); each has a **goal**, the **key
work**, and an **acceptance test**. §3 is the standing principles every milestone
honours. The sequence is deliberate: reporting/observability first (M1) so that scan
behaviour becomes *measurable*, which is exactly what lets us redefine scans cleanly
(M2); everything after composes on those two.

## 1. Where we stand (shipped substrate — keep, don't redo)

- **Recon engine** — concurrent, context-cancellable: DNS (A/AAAA/MX/NS/TXT), WHOIS,
  technology fingerprinting, passive intel (crt.sh, Wayback), subdomain enumeration.
- **Crawler & fuzzer** — domain-scoped crawl (emails/phones/links); directory, vhost,
  and subdomain fuzzing with embedded wordlists.
- **OSINT layer** — email (HIBP/Hunter.io), social (Sherlock), domain enrichment
  (Shodan/Wayback), assembled into an **entity model** (`Target` recon hub ↔ `Entity`
  OSINT hub; per-source `OSINTProfile`s; harvested, deduped contacts; structured
  `DomainInfo`). The Browsint consolidation is complete; `import-browsint` migrates
  legacy data.
- **Persistence & export** — pure-Go SQLite (single static binary); JSON/HTML/CSV/PDF
  report export.

The gap the plan closes: scans are **opaque** (you can't see what a run did, how many
requests it made, or how long each phase took), the mode names are **confusing**
(basic/deep/stealth/aggressive/custom), capabilities are **monolithic** (not usable or
pipeable one at a time), and detection is **hardcoded** (tech rules live in Go, not
data).

## 2. Milestones

### M1 · Reporting & observability *(the priority)*

**Goal.** A scan is a fully **observable run**: you can account for every request it
made, every finding it produced, and how long each phase took — and render that into a
report that looks professional enough to hand to a client.

**Key work.**
- **Run record.** Every scan produces a persisted run: id, target, level, resolved
  config, start/end, wall-clock duration, **total + per-module request counts**, sources
  queried, and errors. One run = one row you can list, diff, and re-render.
- **Structured event stream (JSONL).** Append-only, timestamped events (phase
  start/stop, each outbound request, each finding, each error) — the observability
  backbone. `--output jsonl` streams it live; the report renders *from* it, so the
  report is deterministic and maps 1:1 to what actually happened.
- **Redesigned HTML report.** Self-contained, light/dark, responsive: executive
  summary → asset inventory (hosts/subdomains/tech/ports) → findings with per-finding
  **evidence** → a run **timeline** and request-accounting panel. Consistent visual
  system across sections.
- **Machine outputs.** Findings as JSON and a findings-schema suitable for ingestion
  (stable field names, severity, evidence, source-run id).
- **Live telemetry.** Progress surfaces per-module timing and running request count as
  the scan proceeds — the same numbers that land in the run record.

**Acceptance.** After any scan, `gosint report <run-id>` renders a report in which
every finding traces to an event and every outbound request is accounted for, with
per-phase timing; re-running the report from the stored JSONL reproduces it byte-stable.

### M2 · Scan levels — simple, clear, defined by requests & time

**Goal.** Replace the five confusing modes with **three levels** a user can reason
about instantly, each defined by *what network activity it performs* and *how long it
takes* — numbers M1 now makes real.

**Key work.**
- Collapse `basic/deep/stealth/aggressive/custom` into **three levels**, selected with a
  single `--level` (default **fast**):

  | Level | What it does (request profile) | Active brute / fuzz | Typical time |
  |-------|--------------------------------|---------------------|--------------|
  | **fast** | DNS + WHOIS + one HTTP fetch for tech + one passive subdomain source (crt.sh). Bounded, low request count. | none | seconds |
  | **complete** | fast + **all** passive subdomain sources + Wayback, bulk-resolve every discovered host, HTTP-probe the live ones, full tech + TLS/cert. Passive only — no target brute-forcing. | none | ~1–3 min |
  | **aggressive** | complete + active subdomain brute-force (wordlist), directory/vhost fuzzing, port scan, active signature checks. Noisy, high request count. | yes | minutes+ |

- **Escalation is explicit.** `fast` and `complete` never brute-force or fuzz a target;
  crossing into active behaviour requires `aggressive` (or an explicit opt-in flag).
- **Rate/OPSEC becomes a knob, not a mode.** The old `stealth` folds into cross-cutting
  `--rate` / `--concurrency` controls usable at any level.
- **Advanced override, not a "level".** Power users can still hand-pick phases
  (`--enable-…`) as an advanced escape hatch, but it is not one of the three headline
  levels.
- Each level **prints its request budget and expected duration up front**, and the run
  record (M1) records actuals against it.

**Acceptance.** `gosint scan example.com` (fast) completes in seconds and the run record
shows zero active/brute requests; `--level aggressive` is the only path that records
brute-force/fuzz requests; the three levels are the only names a new user needs to learn.

### M3 · Composable primitives (pipe-first)

**Goal.** Every capability is a small, single-purpose command that reads targets from
**stdin** and emits **JSONL** to stdout, so they chain in a pipeline instead of only
running inside the monolithic scanner.

**Key work.**
- Expose the phases as standalone verbs (subdomains, resolve, http-probe, detect, fuzz,
  ports) that all speak the same line-oriented JSON contract.
- `--silent` (values only) and JSONL (full records) output modes on each.
- Make the `scan` levels *orchestrations* of these primitives, so the pipeline and the
  one-shot scan share exactly one code path.

**Acceptance.** `gosint subdomains example.com | gosint resolve | gosint http-probe`
produces the same live-host set that `scan --level complete` does, and each stage is
independently usable and scriptable.

### M4 · HTTP probing toolkit

**Goal.** Turn "tech detection" into a rich, fast HTTP probe that is the backbone of
both recon and the report's asset inventory.

**Key work.**
- Per-host metadata: status chain, title, technologies, response + favicon hashes,
  TLS/cert details, detected **CDN/WAF/cloud**, and open web ports.
- High-concurrency, rate-aware, resumable across large host lists.
- Feed structured host records into the entity model and the M1 report inventory.

**Acceptance.** Probing a host list yields one structured record per host with the
fields above, and the report's asset inventory is populated entirely from these records.

### M5 · Data-defined detection engine

**Goal.** Move detection out of Go and into **templates/signatures** so coverage grows
by adding data, not code — and users can extend it.

**Key work.**
- A YAML signature format with request + **matcher/extractor** semantics for
  tech-fingerprinting, exposures, and misconfigurations.
- A runner that executes signatures against probed hosts and emits findings with
  evidence into the M1 stream.
- A bundled starter signature set + a user template directory; the hardcoded tech
  detectors are reimplemented as signatures.

**Acceptance.** Adding a new detection is a new YAML file (no rebuild); the existing
tech detections all pass as signatures; findings carry the signature id + evidence.

### M6 · Deeper discovery

**Goal.** Broaden and speed up the discovery surface without sacrificing the
passive-first default.

**Key work.**
- **Pluggable passive sources** for subdomains — aggregate many OSINT providers behind a
  common interface, keyed from config, with graceful degradation when keys are absent.
- **DNS toolkit** — bulk resolution, wildcard detection/filtering, and permutation/
  wordlist brute-force (aggressive level only).
- **Port scanning** — a fast connect/top-ports scan feeding the HTTP probe (M4).

**Acceptance.** `complete` aggregates ≥N passive sources for subdomains; wildcard DNS no
longer inflates results; `aggressive` adds resolved brute-forced hosts and open ports to
the inventory.

### M7 · Config, rate-control & ergonomics

**Goal.** Make the tool pleasant and safe to run at scale.

**Key work.**
- Unified **provider config** (`~/.gosint/provider-config.yaml`) for API keys and
  per-source options, superseding scattered env vars (env still honoured).
- Global **rate-limiting / concurrency** controls (the home for the retired stealth
  behaviour) and **resumable** runs.
- Output routing (stdout / file / directory) and optional completion **notifications**.

**Acceptance.** Keys and rate limits come from one documented config; a large scan can
be interrupted and resumed; output destination is fully controllable.

## 3. Principles (every milestone honours these)

- **Passive by default; escalation is explicit.** Nothing brute-forces or fuzzes a
  target unless the user chose `aggressive` (or an explicit opt-in).
- **Every request is accounted for.** If the tool made a network request, the run record
  and event stream can show it. Observability is not optional.
- **Composable single-purpose primitives.** Small verbs that pipe, over one monolith.
  The scanner orchestrates the same primitives users can run by hand.
- **Data-defined over hardcoded.** Detection grows by adding templates, not code.
- **Deterministic reports.** A report is a pure render of a stored run; same run → same
  report.
- **Keys optional, degrade gracefully.** Missing an API key narrows results, never
  breaks a run.
- **One static binary.** Pure-Go, no cgo, no system dependencies — this stays true.

---

*Working backlog (leverage-ordered task list synced to these milestones):
`.agent/backlog/BACKLOG.md`.*
