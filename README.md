# LLM Self-Reflection Threat Detection — Web Demo

An interactive full-stack web application that demonstrates a **three-level LLM self-reflection pipeline** for cybersecurity threat detection. Submit raw threat data, watch the agent reason in real time, and compare accuracy, latency, and cost across reflection levels.

---

## What It Does

The system runs submitted text through up to three reflection rounds, each powered by a large language model:

| Level | Name | Description |
|-------|------|-------------|
| **L0** | Baseline | Single-pass classification. Fast and cheap — establishes the performance floor. |
| **L1** | Self-Critique | The agent reviews its own initial verdict, reconsidering feature interpretations. |
| **L2** | Consensus Loop | Iterative rounds until the agent agrees with itself across consecutive passes (max 3). |

Each level can use a **different model**, letting you explore asymmetric configurations like a cheap L0 screener and a more powerful L1/L2 critic.

---

## Tech Stack

### Frontend
- **Next.js 16** (App Router) + **React 19**
- **Tailwind CSS v4**
- Real-time streaming via **Server-Sent Events (SSE)**
- Lightweight CSS bar charts for cost/latency analysis (no chart library)

### Backend
- **FastAPI** (Python 3.12+) with async SSE streaming
- **`google-genai` SDK** for Gemini models
- **OpenAI-compatible client** for OpenRouter free-tier models
- Per-call token and latency tracking included in the stream

---

## Supported Models

| Model | Provider | Approx. Cost |
|-------|----------|--------------|
| `gemini-2.5-flash-lite` | Google Gemini | ~$0.001 / query |
| `gemini-2.5-flash` | Google Gemini | ~$0.005 / query |
| `nvidia/nemotron-3-nano-30b:free` | OpenRouter | Free |
| `nvidia/nemotron-3-super-120b:free` | OpenRouter | Free |

---

## Project Structure

```
.
├── frontend/                        # Next.js web app
│   ├── src/
│   │   ├── app/                     # App Router pages + global CSS
│   │   └── components/
│   │       ├── Hero.tsx
│   │       ├── HowItWorks.tsx       # 3-step process explainer
│   │       ├── ModelTiers.tsx       # L0 / L1 / L2 architecture cards
│   │       ├── Domains.tsx          # Detection domain showcase
│   │       ├── DemoSection.tsx      # ← main interactive demo
│   │       ├── Stats.tsx
│   │       └── Footer.tsx
│   └── public/                      # Static assets (level diagrams)
│
└── backend/                         # FastAPI API server
    ├── main.py
    └── app/
        ├── api/routes/analyze.py    # SSE streaming endpoint
        ├── core/config.py           # model config + pricing
        ├── services/
        │   ├── reflection.py        # L0 / L1 / L2 runners
        │   └── prompts.py           # domain-specific prompts
        └── models/schemas.py
```

---

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Python 3.12+
- [`uv`](https://github.com/astral-sh/uv) (fast Python package manager)
- A **Google Gemini API key** — free at [aistudio.google.com](https://aistudio.google.com)
- *(Optional)* An **OpenRouter API key** for free-tier cloud models

---

### 1. Backend

```bash
cd backend

# Install dependencies with uv
uv sync

# Create your environment file
echo "GEMINI_API_KEY=your_key_here" > .env

# Start the server
uv run uvicorn main:app --reload --port 8000
```

API available at `http://localhost:8000` — interactive docs at `/docs`.

---

### 2. Frontend

```bash
cd frontend

npm install
npm run dev
```

Open `http://localhost:3000`.

---

### Environment Variables

Create `backend/.env`:

```env
# Required
GEMINI_API_KEY=your_google_gemini_api_key

# Optional — enables OpenRouter free models in the UI
OPENROUTER_API_KEY=your_openrouter_api_key

# Optional — override default model per level
L0_MODEL=gemini-2.5-flash-lite
L1_MODEL=gemini-2.5-flash
L2_MODEL=gemini-2.5-flash
```

---

## API Reference

### `POST /analyze`

Streams the full L0 → L1 → L2 pipeline as Server-Sent Events.

**Request body:**
```json
{
  "input": "raw threat data (email text, log sequence, network features...)",
  "l0_model": "gemini-2.5-flash-lite",
  "l1_model": "gemini-2.5-flash",
  "l2_model": "gemini-2.5-flash"
}
```

**SSE events streamed back:**

| Event | Fired when |
|-------|------------|
| `l0_thinking` | L0 call started |
| `l0_result` | L0 classification complete |
| `l1_thinking` | L1 critique started |
| `l1_result` | L1 revision complete |
| `l2_thinking` | L2 consensus round started |
| `l2_result` | Final consensus reached |
| `error` | Pipeline failure (with message) |

Each result event includes `label`, `confidence`, `explanation`, `tokens`, `cost_usd`, and `wall_time_s`.

---

## Detection Domains

The demo works on any free-text threat data, and is specifically tuned for:

| Domain | Example Input |
|--------|---------------|
| **Phishing Email** | Raw email with headers + body |
| **Network Intrusion** | NSL-KDD feature string |
| **Malware (PE)** | ClaMP static analysis features |
| **Log Anomaly** | Sequence of employee activity events |

---

## Research Background

This web app is the interactive prototype for the research paper:

> **"LLM Self-Reflection for Security Threat Detection: A Multi-Level Agentic Approach"**  
> Arnav Pandey, Aditya Kumar Jha, Adarsh Raj — IIIT Naya Raipur

**Key finding:** self-reflection reliably *degrades* detection performance at both capability extremes — weak models produce flawed critique, strong models are already at ceiling. We call this the **Self-Reflection Paradox**. The web demo lets you observe this live by comparing L0 vs L1 vs L2 verdicts on the same input.

---

## License

MIT
