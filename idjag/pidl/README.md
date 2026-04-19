# ID-JAG Protocol Definitions (PIDL)

This directory contains [PIDL](https://github.com/grokify/pidl) definitions for ID-JAG flows.

## Files

| File | Description |
|------|-------------|
| `idjag_simple.json` | Agent-only authentication (no human delegation) |
| `idjag_delegation.json` | Human-to-agent delegation with actor claim |

## Generated Diagrams

Diagrams are generated using the `pidl` CLI tool:

| Format | Simple Flow | Delegation Flow |
|--------|-------------|-----------------|
| PlantUML | `idjag_simple.puml` | `idjag_delegation.puml` |
| Mermaid | `idjag_simple.mmd` | `idjag_delegation.mmd` |
| Graphviz DOT | `idjag_simple.dot` | `idjag_delegation.dot` |

## Regenerating Diagrams

Install the PIDL CLI:

```bash
go install github.com/grokify/idjag/pidl/cmd/pidl@latest
```

Validate definitions:

```bash
pidl validate idjag/pidl/*.json
```

Generate all formats:

```bash
# PlantUML
pidl generate -f plantuml -o idjag/pidl/idjag_simple.puml idjag/pidl/idjag_simple.json
pidl generate -f plantuml -o idjag/pidl/idjag_delegation.puml idjag/pidl/idjag_delegation.json

# Mermaid
pidl generate -f mermaid -o idjag/pidl/idjag_simple.mmd idjag/pidl/idjag_simple.json
pidl generate -f mermaid -o idjag/pidl/idjag_delegation.mmd idjag/pidl/idjag_delegation.json

# Graphviz DOT
pidl generate -f dot -o idjag/pidl/idjag_simple.dot idjag/pidl/idjag_simple.json
pidl generate -f dot -o idjag/pidl/idjag_delegation.dot idjag/pidl/idjag_delegation.json
```

## Rendering to Images

### PlantUML to SVG/PNG

```bash
# Using PlantUML jar
java -jar plantuml.jar -tsvg idjag/pidl/idjag_simple.puml

# Using PlantUML server
curl -X POST --data-binary @idjag/pidl/idjag_simple.puml https://www.plantuml.com/plantuml/svg/
```

### Mermaid to SVG/PNG

```bash
# Using mermaid-cli (mmdc)
npx @mermaid-js/mermaid-cli -i idjag/pidl/idjag_simple.mmd -o idjag/pidl/idjag_simple.svg
```

### Graphviz DOT to SVG/PNG

```bash
dot -Tsvg idjag/pidl/idjag_simple.dot -o idjag/pidl/idjag_simple_flow.svg
dot -Tpng idjag/pidl/idjag_delegation.dot -o idjag/pidl/idjag_delegation_flow.png
```

## Protocol Structure

### Simple Flow (Agent-Only)

```
Agent → Assertion Issuer → Authorization Server → Resource Server
```

The agent authenticates as itself without human delegation:

- **Subject (`sub`)**: Agent's identity (e.g., `agent:calendar-bot`)
- **No actor claim**: Agent is both subject and actor

### Delegation Flow (Human-to-Agent)

```
Human → Identity Provider → Agent → Authorization Server → Resource Server
```

The agent acts on behalf of a human user:

- **Subject (`sub`)**: Human user's identity (e.g., `user:alice`)
- **Actor (`act`)**: Agent's identity (e.g., `agent:calendar-bot`)

Both identities are preserved through the token exchange, enabling:

- Authorization based on human permissions
- Audit trails showing both who authorized and who acted
- Agent-specific policies and restrictions
