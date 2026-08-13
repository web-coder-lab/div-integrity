# Div Integrity — 8 Server Backend

Passive mobile integrity control plane. **Does not modify or cross Free Fire / any game.**

## Live (Render free)

| Service | URL |
|---------|-----|
| Auth + Admin | https://div-auth.onrender.com |
| Admin UI | https://div-auth.onrender.com/admin.html |
| User link + Aggregator | https://div-user-link.onrender.com |
| Deep A | https://div-scan-deep-a.onrender.com |
| Deep B | https://div-scan-deep-b.onrender.com |
| Dark A | https://div-scan-dark-a.onrender.com |
| Dark B | https://div-scan-dark-b.onrender.com |
| AI Light | https://div-ai-light.onrender.com |
| AI Heavy | https://div-ai-heavy.onrender.com |

## Phases 1–12 complete

Auth → Link/Consent → Service auth → Deep scan → Dark observe → Popup intake → AI triage → Heavy jobs → Aggregator → Admin → Hardening

## Env (shared)

```
JWT_SECRET=
SERVICE_SECRET=
XAI_API_KEY=          # optional Grok
EXPLORIUM_API_KEY=    # optional Explorium
GITHUB_TOKEN=         # optional heavy jobs
```

## Rule
No auth / no consent → no scan.
