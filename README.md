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
ollama pull llama3.1:8b
```

## Usage

### Basic - test a chat endpoint

```bash
python a2a_agent.py --target http://localhost:8000/chat --model llama3.1:8b --turns 30
```

### Auto-detect Ollama targets

If the target is an Ollama server, the agent auto-detects available models:

```bash
python a2a_agent.py --target http://somehost:11434
```

### Test OpenAI-compatible APIs

```bash
python a2a_agent.py --target https://api.x.ai/v1 --api-key $XAI_KEY --api-model grok-3
```

### Custom chat endpoints

```bash
python a2a_agent.py --target https://example.com \
  --chat-endpoint /api/question \
  --chat-field query \
  --chat-response answer,text \
  --chat-header "Authorization: Bearer TOKEN"
```

### WebSocket / SignalR targets

```bash
python a2a_agent.py --target wss://example.com/chat --websocket
```

### Advanced options

```bash
# Enable reasoning mode for smarter attacks
python a2a_agent.py --target http://localhost:8000/chat -r --turns 50

# OAST/SSRF testing with callback
python a2a_agent.py --target http://localhost:8000/chat --oast https://xyz.oast.fun

# Deep token testing (tokenization exploits, training data extraction)
python a2a_agent.py --target http://localhost:8000/chat --deep-token

# Fresh/fine-tuned model testing
python a2a_agent.py --target http://localhost:11434 --fresh-model

# Filter attack categories
python a2a_agent.py --target http://localhost:8000/chat --list-categories
python a2a_agent.py --target http://localhost:8000/chat --attack-categories emoji_smuggling,unicode_smuggling

# Provide target context for smarter attacks
python a2a_agent.py --target http://localhost:8000/chat \
  --target-context "e-commerce shopping bot with product catalog and order data access"
```

## Target App (Intentionally Vulnerable)

A FastAPI chatbot with real secrets, user database, and leaky endpoints - designed as a practice target.

```bash
cd target_app
chmod +x run.sh
./run.sh deepseek-r1:8b    # or any model from your ollama list
```

Then in another terminal:

```bash
python a2a_agent.py --target http://localhost:8000/chat --turns 50
```

See [target_app/README.md](target_app/README.md) for details on the endpoints and secrets to extract.

## How It Works

1. The agent connects to the target and probes its capabilities
2. A local Ollama LLM generates adaptive attack prompts based on target responses
3. The agent maintains conversation history and strategic memory
4. Attack strategies evolve based on what works - successful techniques get amplified
5. Results are saved as timestamped JSON reports

## Disclaimer

This tool is for authorized security testing only. Only use it against systems you own or have explicit permission to test.

## License

MIT
