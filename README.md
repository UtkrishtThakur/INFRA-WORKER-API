Stateless Gateway that protects backends before traffic reaches them

The Worker is the data plane of Antigravity.
It sits in front of real backends and decides who is allowed in and who is not.

It does not store data, does not own configuration, and does not expose dashboards.
Its only job is to process traffic fast and safely.

🧠 What this service actually does

For every incoming request, the Worker:

Extracts the API key

Identifies which project the request belongs to

Applies rate limiting and abuse checks

Decides whether to allow or block the request

Proxies allowed traffic to the real backend

If anything looks wrong → the request never reaches the backend.

🏗️ Where it fits in the system
Client
  ↓
Antigravity Worker (this repo)
  ↓
Customer Backend (Upstream API)


The Worker gets its configuration from the Control API and keeps it in memory.

✨ Key Characteristics

Stateless

No database

Fast

Horizontally scalable

Fail-closed (unknown traffic is blocked)

This is intentional.
All state lives elsewhere.

📦 Tech Stack

FastAPI

httpx (proxying)

Redis (rate limiting)

Async Python

In-memory config cache

🔐 Security Model

API keys are never stored in raw form

Worker only sees hashed keys

Invalid or missing keys are rejected immediately

Rate limits and abuse checks happen before proxying

Backend never sees unauthorized traffic

🔄 Configuration Flow

The Worker does not manage projects or keys.

Instead, it periodically fetches config from the Control API:

GET /internal/worker/config
x-worker-secret: <shared-secret>


The response contains:

Project IDs

Upstream URLs

Allowed API key hashes

This config is stored in memory and refreshed periodically.

🌍 Environment Variables

Create a .env file:

ENV=production

# Redis (rate limiting)
REDIS_URL=redis://default:password@host:6379

# Control API (config source)
CONTROL_API_BASE_URL=https://control.antigravity.io

# Shared secret for worker authentication
CONTROL_WORKER_SHARED_SECRET=super-long-random-string


⚠️ CONTROL_WORKER_SHARED_SECRET must match the Control API.

▶️ Running Locally
1️⃣ Install dependencies
pip install -r requirements.txt

2️⃣ Start the worker
uvicorn main:app --reload


The worker will:

Start immediately

Begin fetching config in the background

Accept traffic once config is available

🚦 Request Lifecycle (Step-by-step)

Client sends request to gateway URL

Worker extracts X-API-Key

API key is hashed and validated

Rate limit is checked via Redis

Risk score / decision engine runs

Request is either:

❌ Blocked (401 / 429)

✅ Proxied to upstream backend

Backends remain unaware of any of this logic.

📊 Logging

Each request produces structured logs including:

Project ID

Path

IP address

Decision (allowed / blocked)

Risk score

Currently logged to stdout.
Designed to plug into centralized logging later.

🚀 Deployment Notes

Deploy as a stateless service

Multiple replicas are safe

No DB migrations required

Can be restarted anytime

Should be deployed after Control API

🧪 Status

✅ MVP complete

🔄 Production-ready core

📈 Designed for scaling

🧠 Design Philosophy

“If traffic reaches the backend, it should already be trusted.”

The Worker is intentionally strict:

Unknown → blocked

Invalid → blocked

Abusive → blocked

Backends stay simple and focused.
