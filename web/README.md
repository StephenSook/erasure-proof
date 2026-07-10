# web (demo console)

The browser-facing demo for erasure-proof: a plain-UI six-stage console that walks the erasure loop
(store a memory, show the leak, inspect the envelope, crypto-erase, survive a node kill, prove it),
wired to the live API. The anime.js motion layer is added on top of this later.

## Stack

React 19 + TypeScript + Vite. react-router for the routes. Plain CSS custom properties (no Tailwind);
the design tokens (warm near-black + neon per-stage hues) live in `src/styles/tokens.css`. vitest +
Testing Library. No backend is required to run it (see mock mode).

## Run

```
cd web
npm install
npm run dev          # http://localhost:5173, proxies /api, /memories, /erase to localhost:8080
```

Against a live local stack, start the Go api on :8080 first. To run standalone with canned data:

```
VITE_USE_MOCK=1 npm run dev
```

`VITE_API_BASE` overrides the api origin (default: relative, same-origin behind CloudFront in prod).

## Checks

```
npm run typecheck    # tsc --noEmit
npm run lint         # eslint (flat config)
npm run test         # vitest run
npm run build        # vite build -> dist/
```

## Routes

- `/` landing
- `/demo` the six-stage console (the judged surface)
- `/trust` the honesty page (what is live, recorded, or local)

## Layout

- `src/api/` typed client (`client.ts` real fetch, `mock.ts` canned, `index.ts` picks by env)
- `src/data/demoMemory.ts` the demo subject's real GTR embedding (from `db/seed`)
- `src/demoStages.ts` the six-stage metadata (title, hue, description)
- `src/useDemo.ts` the state machine driving the loop
- `src/components/` Stage, KeyValue, CodeBlock, Badge, StatusDot
- `src/pages/` DemoConsole, Trust, Landing
