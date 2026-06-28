<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=MAGICID&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="MAGICID"/>

# MAGICID

### Identify true file types by magic bytes (beats extensions)

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Identify+true+file+types+by+magic+bytes+beats+extensions;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-magicid.svg?color=6b46c1)](https://pypi.org/project/cognis-magicid/) [![CI](https://github.com/cognis-digital/magicid/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/magicid/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-magicid
magicid scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ magicid-emit --version
magicid 0.1.0
```

```console
$ magicid-emit --help
usage: magicid [-h] [--version] {scan} ...

Identify true file types by magic bytes (beats extensions).

positional arguments:
  {scan}
    scan      Identify true file types of PATH(s).

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit
```

> Blocks above are real `magicid` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"magicid": {
"platform": "stix",
"findings": [
{
"id": "1234567890abcdef",
"created_by_ref": "user1",
"created_at": "2023-02-15T14:30:00Z",
"name": "Suspicious Network Traffic",
"description": "Network traffic anomaly detected",
"labels": ["network", "suspicious"],
"objects": [
{
"id": "object1",
"type": "indicator",
"value": "192.168.1.100"
},
{
"id": "object2",
"type": "observable",
"value": "tcp/12345"
}
]
}
]
}
```

<!-- cognis:example:end -->

## Usage — step by step

1. **Install** (Python 3.8+, stdlib only):
   ```bash
   pip install magicid
   ```
2. **Scan files** to identify their true type by magic bytes (catches extension spoofing):
   ```bash
   magicid scan uploads/*.png suspicious.pdf
   ```
   Exits `1` when findings exist (mismatch / unknown / unreadable), `0` when all consistent.
3. **Recurse a directory tree**:
   ```bash
   magicid scan --recursive ./uploads
   ```
4. **Read the output as JSON or write an HTML report**:
   ```bash
   magicid --format json scan ./uploads | jq '.summary, .results[] | select(.severity=="high")'
   magicid --format html --out report.html scan ./uploads
   ```
   JSON includes `summary` (high/medium/low/ok counts) and per-file `results[]`.
5. **Gate an upload pipeline / CI** — block files whose real type contradicts their extension:
   ```bash
   magicid scan ./incoming/* || { echo "type-mismatch detected"; exit 1; }
   ```


## Contents

- [Why magicid?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why magicid?

Identify true file types by magic bytes (beats extensions) — without standing up heavyweight infrastructure.

`magicid` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Identify Bytes
- ✅ Identify File
- ✅ Scan Paths
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-magicid
magicid --version
magicid scan .                       # scan current project
magicid scan . --format json         # machine-readable
magicid scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ magicid scan .
  [HIGH    ] MAG-001  example finding             (./src/app.py)
  [MEDIUM  ] MAG-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[input] --> P[magicid<br/>analyze + score]
  P --> OUT[report]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`magicid` is interoperable with every popular way of using AI:

- **MCP server** — `magicid mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `magicid scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis magicid** | typical tools |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |
<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`magicid mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/magicid.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/magicid.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/magicid.git" # uv
pip install cognis-magicid                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/magicid:latest --help        # Docker
brew install cognis-digital/tap/magicid                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/magicid/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/magicid` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools


**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `magicid` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
