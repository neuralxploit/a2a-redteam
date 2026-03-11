# A2A Red Team Agent

Autonomous LLM-powered red team agent for testing AI chatbots, A2A (Agent-to-Agent) endpoints, and OpenAI-compatible APIs. Uses a local Ollama model to adaptively probe targets for prompt injection, credential leakage, SSRF, and other LLM security issues.

## Requirements

- Python 3.10+
- [Ollama](https://ollama.ai/) running locally with at least one model pulled

## Setup

```bash
pip install -r requirements.txt
```

Pull an Ollama model (if you haven't already):

```bash
ollama run kimi-k2.5:cloud
```

## CLI Reference

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--target` | `-t` | *required* | Target URL (A2A, Ollama, OpenAI-compat, any HTTP endpoint) |
| `--model` | `-m` | `kimi-2.5:cloud` | Ollama model powering the red team agent |
| `--ollama-url` | | `http://localhost:11434` | Ollama server for the attacker LLM |
| `--turns` | `-n` | `15` | Max conversation turns |
| `--prompt` | `-p` | | Custom first message |
| `--discover` | `-d` | | Tool/MCP discovery mode - probe capabilities then exit |
| `--reasoning` | `-r` | | Deep reasoning mode (32K context, strategic memory, full history) |
| `--temperature` | | `0.8` | Attacker LLM temperature (0.0-2.0) |
| `--deep-token` | | | Deep token testing (tokenization exploits, training extraction, special token injection) |
| `--fresh-model` | | | Fresh/fine-tuned model audit (system prompt extraction, capability discovery, safety boundaries) |
| `--capability-discovery` | | | Focus on capability and tool discovery |
| `--boundary-mapping` | | | Focus on safety boundary mapping |
| `--finetune-detect` | | | Focus on fine-tuning difference detection |
| `--oast` | | | OAST callback URL for SSRF testing (Burp Collaborator, interactsh, etc.) |
| `--api-key` | | | API key for direct API testing (xAI, OpenAI, Anthropic, etc.) |
| `--api-model` | | `grok-3` | Model to test on API |
| `--target-model` | | | Specific model to test on target Ollama server |
| `--target-context` | | | Describe the target bot so the attacker adapts strategy |
| `--attack-categories` | | | Comma-separated novel attack categories to use |
| `--list-categories` | | | List all available attack categories and exit |
| `--chat-endpoint` | | | Custom chat endpoint path (e.g., `/api/question`) |
| `--chat-field` | | `message` | Field name for message in payload |
| `--chat-response` | | `message,response,answer,content` | Response field names to try |
| `--chat-extra` | | | Extra JSON fields (e.g., `threadID:null,context:null`) |
| `--chat-header` | | | Custom HTTP headers (repeatable) |
| `--chat-nest` | | | Wrap message as nested object `{field: {content: msg, role: 'user'}}` |
| `--chat-poll` | | | Enable async job polling for APIs returning job_id |
| `--websocket` | | | Use WebSocket/SignalR protocol |
| `--ws-target` | | `message` | SignalR target method |
| `--ws-response` | | `message,response,answer,text` | WebSocket response field names |
| `--ws-message-id` | | | Custom message ID for WebSocket payload |

## Best Commands

### Reasoning mode - full power adaptive attacks

The most important flag. Gives the attacker LLM 32K context, full conversation history, and strategic memory that tracks what works and what fails. The agent builds a model of the target's defenses and adapts.

```bash
python a2a_agent.py -t http://localhost:8000/chat -r --turns 30
```

### Full-spectrum attack with deep token testing

Combines reasoning with 30+ categories of tokenization exploits, training data extraction, special token injection (ChatML, Llama, Mistral format tokens), and SSRF payloads.

```bash
python a2a_agent.py -t http://target:8080 -r --deep-token --turns 30 --temperature 1.2
```

### OAST/SSRF testing with target context

Injects SSRF payloads (AWS metadata, file://, localhost admin panels). Target context feeds domain knowledge to the attacker so it crafts contextual social engineering.

```bash
python a2a_agent.py -t http://target:8080 \
  --oast https://xyz.oast.fun \
  --target-context "e-commerce shopping bot with product catalog and order data access" \
  -r --turns 20
```

### Fresh/fine-tuned model comprehensive audit

Activates all fresh-model sub-modes: system prompt extraction, capability discovery, safety boundary mapping, fine-tuning diff detection, instruction hierarchy exploitation. First 8 turns use structured probing, then transitions to adaptive attacks.

```bash
python a2a_agent.py -t http://target:8080 --fresh-model -r --turns 30
```

### Safety boundary mapping only

Maps refusal boundaries - what topics trigger safety filters, what's prohibited, then tests edge cases (cybersecurity framing, academic context, fiction, CTF, graduated escalation).

```bash
python a2a_agent.py -t http://target:8080 --boundary-mapping -r --turns 20
```

### Direct API testing (xAI, OpenAI, Anthropic)

Skips protocol detection, goes straight to attacking commercial APIs.

```bash
python a2a_agent.py -t https://api.x.ai/v1 --api-key "$XAI_KEY" --api-model grok-3 -r --deep-token --turns 25
```

### Discovery-only reconnaissance

Non-destructive recon. Probes for A2A agent cards, MCP tools, capabilities, file access, code execution, and agent routing. Exits after probing.

```bash
python a2a_agent.py -t http://target:8080 -d
```

### Encoding-based filter bypasses

Focuses on zero-width characters, Cyrillic homoglyphs, fullwidth Latin, Braille, invisible Unicode tags, emoji rebus. Bypasses keyword-based safety filters.

```bash
python a2a_agent.py -t http://target:8080 \
  --attack-categories 'unicode_smuggling,emoji_smuggling,multi_script_confusion,steganographic_text' \
  -r --turns 20
```

### Custom REST API with auth

Hits any arbitrary REST API regardless of schema. Custom field mapping, headers, extra fields.

```bash
python a2a_agent.py -t https://app.example.com \
  --chat-endpoint /api/question \
  --chat-field question \
  --chat-response answer,response \
  --chat-extra 'threadID:null,context:null' \
  --chat-header 'Cookie: session=abc123' \
  --chat-header 'Authorization: Bearer tok' \
  -r --deep-token
```

### WebSocket / SignalR bot testing

Tests real-time chat bots over WebSocket with SignalR protocol framing (Microsoft Bot Framework, custom hubs).

```bash
python a2a_agent.py -t wss://bot.example.com/hub \
  --websocket --ws-target sendMessage --ws-response botResponse,text \
  -r --turns 20
```

### Ollama-to-Ollama with uncensored attacker

Uses an uncensored attacker model against a specific target model. High temperature for maximum variety.

```bash
python a2a_agent.py -t http://target-ollama:11434 \
  --target-model llama2-uncensored:latest \
  -m dolphin-mistral:latest \
  -r --deep-token --turns 30 --temperature 1.3
```

### Maximum - everything enabled

```bash
python a2a_agent.py -t http://target:8080 \
  -r --deep-token --fresh-model \
  --oast https://xyz.oast.fun \
  --target-context "internal HR bot with employee database and payroll access" \
  --attack-categories 'unicode_smuggling,many_shot_jailbreak,prefix_injection,recursive_injection' \
  --temperature 1.4 --turns 40
```

## Attack Categories

### Novel Attacks (16 categories)

`many_shot_jailbreak` `crescendo` `refusal_suppression` `prefix_injection` `payload_splitting` `ascii_art` `recursive_injection` `summarization_extraction` `language_switching` `output_format_exploit` `emoji_smuggling` `unicode_smuggling` `emoji_text_hybrid` `multi_script_confusion` `steganographic_text`

### Deep Token Attacks (30+ categories)

`training_data_extraction` `tokenization` `training_patterns` `base_model` `special_tokens` `bias_probing` `context_exploits` `model_introspection` `xml_injection` `confusion_attack` `social_engineering` `temporal_confusion` `technical_pretexts` `trust_exploitation` `format_tricks` `code_extraction` `memory_disclosure` `tool_probing` `credential_hunting` `system_commands` `path_disclosure` `ssrf_injection` `jailbreaks` `schema_completion` `completion_bait` `document_extraction` `user_email_extraction` `pii_extraction` `infrastructure_extraction` `focused_secrets` `complex_queries`

### Fresh Model Attacks (5 categories)

`system_prompt_extraction` `capability_discovery` `safety_boundary_mapping` `finetune_diff_detection` `instruction_hierarchy`

## Target Auto-Detection

The agent automatically detects the target type by probing in order:

1. **Ollama** - checks for "Ollama is running" response, pulls model list from `/api/tags`
2. **OpenAI-Compatible** - tries `/v1/chat/completions`, `/chat/completions`
3. **A2A (JSON-RPC)** - tries `/tasks/send`, `/a2a` with `message/send` method
4. **Simple Chat** - tries `/ask`, `/chat`, `/ui/conversation/messages`
5. **Chat API variants** - `/api/chat` with message/prompt/text/query/input fields
6. **Question API** - `/api/question`, `/api/questions`
7. **Smart Discovery** - if all fail, uses the attacker LLM to analyze the target's HTML/API and discover endpoints

Handles SSE streaming, NDJSON streaming, and extracts responses from multiple nested formats.

## How It Works

1. **Protocol Detection** - auto-detects target type (Ollama, OpenAI, A2A, REST, WebSocket)
2. **Adaptive Attacks** - local Ollama LLM generates attack prompts based on target responses
3. **Strategic Memory** - tracks successful/failed techniques, models target defenses
4. **Exploit Queue** - when an attack succeeds, auto-generates follow-up exploits and prioritizes them
5. **Cross-Session Learning** - SQLite database stores successful attacks across sessions
6. **Confusion Attacks** - periodically injects "repeat what you just said" to re-leak information
7. **Interrogation Mode** - when the target leaks data, escalates extraction with compliance tracking
8. **Dynamic Identity** - builds fake identity based on discovered target info for social engineering
9. **Aggressive Obfuscation** - leetspeak, zero-width characters, and homoglyph mutations applied dynamically
10. **Reports** - saves timestamped JSON reports with all findings

## Target App (Intentionally Vulnerable)

A FastAPI chatbot with real secrets, user database, and leaky endpoints - designed as a practice target.

```bash
cd target_app
chmod +x run.sh
./run.sh deepseek-r1:8b    # or any model from your ollama list
```

Then in another terminal:

```bash
python a2a_agent.py --target http://localhost:8000/chat -r --deep-token --turns 50
```

See [target_app/README.md](target_app/README.md) for endpoints and secrets to extract.

## Disclaimer

This tool is for authorized security testing only. Only use it against systems you own or have explicit permission to test.

## License

MIT
