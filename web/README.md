# GuardScan Web

Next.js front end for GuardScan — deploy target for Vercel.

## Stack

- Next.js (App Router) + React 19 + TypeScript
- Tailwind CSS v4
- Geist / Geist Mono
- Recharts (severity breakdown)

## Local

```bash
cp .env.example .env.local
# set OPENROUTER_API_KEY
npm install
npm run dev
```

## Vercel

Import the monorepo, set **Root Directory** to `web`, add `OPENROUTER_API_KEY`.

Detectors run client-side (offline). `/api/scan` adds grounded OpenRouter explanations
with automatic template fallback.
