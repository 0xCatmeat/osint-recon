# osint-recon

A command-line OSINT tool that pulls evidence on a target from a bunch of
providers at once, normalizes everything into one schema, and writes you a tidy
report. Give it a domain, IP, URL, file hash, or EVM address and it fans out to
Shodan, VirusTotal, crt.sh, RDAP, urlscan, and whatever else you have keys for,
then hands back Markdown you can actually read.

It is built for investigation work you might have to repeat or back up later, so
every run keeps the raw provider JSON, the normalized findings, source URLs,
timestamps, cache metadata, and any errors. Nothing gets thrown away, and you
can rebuild the reports afterward without querying a single provider again.

Most of what it does is passive API lookups. A few optional providers shell out
to local tools that touch the target directly. Those only run when you pass
`--active`, so a normal run never probes the target itself.

## Contents

- [What you get](#what-you-get)
- [Requirements](#requirements)
- [Download](#download)
- [Install](#install)
- [API keys](#api-keys)
- [Quick start](#quick-start)
- [Providers](#providers)
- [Commands](#commands)
- [Enrich flags](#enrich-flags)
- [Target types](#target-types)
- [Output](#output)
- [Cache](#cache)
- [Active probing and the scope gate](#active-probing-and-the-scope-gate)
- [Rebuilding reports](#rebuilding-reports)
- [Development](#development)
- [When something is off](#when-something-is-off)

## What you get

- **One target, many sources.** Auto-detects whether you handed it a domain, IP,
  URL, hash, or EVM address, then runs only the providers that make sense for it.
- **Everything kept.** Raw responses, normalized findings, the URL each finding
  came from, and when it was seen all land in one run directory.
- **Readable reports.** A `summary.md` grouped by artifact and provider, plus a
  `sources.md` so anyone can retrace where a finding came from.
- **Cached and rate-limit friendly.** Responses are cached in SQLite, so
  repeated runs and separate commands reuse data instead of burning API quota.
- **Passive by default.** A few local tools probe the target directly. Those
  stay off unless you pass `--active`, so a normal run only does passive lookups.

## Requirements

- Python 3.11 or later
- [`uv`](https://docs.astral.sh/uv/)
- API keys for whichever keyed providers you want (all optional)
- Optional local tools in `~/OSINT/bin/` for the binary-backed providers

You do not need any keys to start. Providers without a key or a binary are just
skipped, so a bare install still gets you RDAP and certificate transparency for
free.

## Download

Clone the repo:

```bash
git clone https://github.com/0xCatmeat/osint-recon.git
cd osint-recon
```

Or grab a GitHub archive:

```bash
curl -L https://github.com/0xCatmeat/osint-recon/archive/refs/heads/main.zip -o osint-recon.zip
unzip osint-recon.zip
cd osint-recon-main
```

## Install

Pull in dependencies with `uv`:

```bash
uv sync
```

Make sure the CLI runs:

```bash
uv run osint-recon --version
```

## API keys

Keys live in an env file. The default path is:

```text
~/OSINT/config/apis.env
```

Point somewhere else with `--env PATH` if you keep yours elsewhere.

```bash
mkdir -p ~/OSINT/config
cp apis.env.example ~/OSINT/config/apis.env
$EDITOR ~/OSINT/config/apis.env
chmod 600 ~/OSINT/config/apis.env
```

The keys it knows about:

```dotenv
SHODAN_API_KEY=your_key
NETLAS_API_KEY=your_key
URLSCAN_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
ETHERSCAN_API_KEY=your_key
```

Only fill in the ones you actually have. Anything left blank is skipped.

## Quick start

See which providers are ready:

```bash
uv run osint-recon doctor
```

Add `--local` to also check the local tools and files:

```bash
uv run osint-recon doctor --local
```

Plan a run before it touches anything:

```bash
uv run osint-recon enrich example.com --dry-run
```

Heads up: for domains, a dry run may still resolve DNS to show you the IP pivots
it would query. Add `--no-pivots` if you want it fully quiet:

```bash
uv run osint-recon enrich example.com --dry-run --no-pivots
```

Run it for real:

```bash
uv run osint-recon enrich example.com
```

Point at a custom env file:

```bash
uv run osint-recon --env ./apis.env enrich example.com
```

Run on an EVM address:

```bash
uv run osint-recon enrich 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B
```

## Providers

| Provider | Key or dependency | Target types | Notes |
|---|---|---|---|
| Shodan | `SHODAN_API_KEY` | IP | Host exposure and CVE data. Search is opt-in because it costs credits. |
| Netlas | `NETLAS_API_KEY` | IP, domain | Host, DNS, certificate, and WHOIS data. |
| urlscan | `URLSCAN_API_KEY` | domain, URL | Existing urlscan results. |
| VirusTotal | `VIRUSTOTAL_API_KEY` | domain, IP, URL, hash | Reputation and analysis stats. |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP | Abuse confidence score and report count. |
| Etherscan | `ETHERSCAN_API_KEY` | EVM address | Ethereum mainnet balance and recent transactions. |
| RDAP | none | domain, IP | Registration data. |
| crt.sh | none | domain | Certificate transparency names. |
| subfinder | `~/OSINT/bin/subfinder` | domain | Passive subdomain discovery via local binary. |
| dnsx | `~/OSINT/bin/dnsx` | domain | DNS records via local binary. Active, needs `--active`. |
| httpx | `~/OSINT/bin/httpx` | domain | HTTP probing via local binary. Active, needs `--active`. |
| tlsx | `~/OSINT/bin/tlsx` | domain, IP | TLS certificate data via local binary. Active, needs `--active`. |
| gau | `~/OSINT/bin/gau` | domain | Historical URLs via local binary. |

`doctor --local` also takes inventory of other common tools it spots in
`~/OSINT/bin/`, such as `mapcidr`, `gitleaks`, `trufflehog`, `nuclei`, `katana`,
and `uncover`.

## Commands

| Command | What it does |
|---|---|
| `doctor` | Checks API keys and provider health. |
| `doctor --local` | Also checks local paths and binaries. |
| `enrich <target>` | Runs providers for a target and writes a report directory. |
| `normalize <run-dir>` | Rebuilds `normalized/findings.jsonl` from stored raw responses. |
| `report <run-dir>` | Rebuilds `summary.md` and `sources.md`. |
| `scope-gate` | Records authorization before active tooling. |

## Enrich flags

| Flag | What it does |
|---|---|
| `--dry-run` | Shows the planned artifacts and providers without querying them. Domain pivots may still resolve DNS. |
| `--json` | Prints machine-readable output. |
| `--out PATH` | Uses a custom reports directory. |
| `--case-id ID` | Sets your own case ID. |
| `--no-pivots` | Turns off domain-to-IP expansion. |
| `--max-pivots N` | Caps how many resolved IPs get queried. Default: `3`. |
| `--active` | Also runs the local tools that probe the target directly (dnsx, httpx, tlsx). Off by default. |
| `--offline` | Uses the provider cache only. Pair with `--no-pivots` to skip DNS too. |
| `--refresh` | Ignores cached responses and fetches fresh. |
| `--max-age SECONDS` | Accepts cache only when it is younger than this. |
| `--shodan-search QUERY` | Runs an opt-in Shodan search. Costs a query credit. |

## Target types

The CLI figures out the target type for you.

| Type | Example |
|---|---|
| `domain` | `example.com` |
| `ip` | `8.8.8.8`, `2606:4700:4700::1111` |
| `url` | `https://example.com/path` |
| `hash` | `d41d8cd98f00b204e9800998ecf8427e` |
| `evm_address` | `0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B` |

For a domain, `enrich` also resolves up to three IPs and runs the IP-capable
providers against those pivots. Use `--no-pivots` if you would rather it stay on
the domain alone.

## Output

By default, runs land under:

```text
~/OSINT/reports/<target>/<timestamp>/
```

Each run holds:

```text
raw/                         raw provider JSON responses
normalized/findings.jsonl    one JSON object per normalized finding
summary.md                   readable findings grouped by artifact and provider
sources.md                   source URLs and observation times
run-metadata.json            target, providers, cache stats, errors, file manifest
```

Run directories are created locked down: directories are mode `700`, files are
mode `600`. The evidence is yours to read, not the rest of the box's.

## Cache

Provider responses get cached in:

```text
~/OSINT/.cache/osint-recon.sqlite
```

That cache is what keeps you from hammering the same APIs, and it lets rate
limits carry across separate runs. Bypass it with `--refresh`, require it with
`--offline`, or only trust recent entries with `--max-age SECONDS`.

## Active probing and the scope gate

Most providers are passive lookups, but three local ones touch the target
directly: dnsx (DNS resolution), httpx (HTTP probing), and tlsx (TLS probing).
They stay off unless you pass `--active`, so a normal `enrich` never probes the
target:

```bash
uv run osint-recon enrich example.com --active
```

Preview what an active run would do first with `--dry-run --active`, and only
turn it on where you actually have permission.

The `scope-gate` command records that permission. It is an audit trail, not a
switch. It writes a JSON record that says you were authorized. It does not enable
`--active` for you and it does not run anything itself:

```bash
uv run osint-recon scope-gate \
  --target example.com \
  --scope-file ./scope.txt \
  --authorization-note "Bug bounty scope allows testing this domain"
```

## Rebuilding reports

Still have a run directory? You can rebuild the normalized findings and the
Markdown straight from the stored raw responses, no provider calls needed:

```bash
uv run osint-recon normalize ~/OSINT/reports/example.com/20260606T120000Z
uv run osint-recon report ~/OSINT/reports/example.com/20260606T120000Z
```

Handy when you change the report format, or when you want fresh Markdown off old
evidence.

## Development

Run the tests:

```bash
uv run pytest
```

Lint and formatting:

```bash
uv run ruff check .
uv run ruff format --check .
```

## When something is off

Keyed providers getting skipped? Check which env file it is reading:

```bash
uv run osint-recon doctor
uv run osint-recon --env ./apis.env doctor
```

Local binary providers failing? Make sure the tools are there and executable:

```bash
uv run osint-recon doctor --local
ls -l ~/OSINT/bin/
```

Want a domain run to make no network calls at all? Drop the pivots and require
cached data:

```bash
uv run osint-recon enrich example.com --offline --no-pivots
```

## License

MIT
