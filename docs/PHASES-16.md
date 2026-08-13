# Div Integrity — 16 Phases

## Phase 1 — User popup + solid connect ✅
- Dialog popup UI only
- Auth health 5 retries (cold start)
- Permissions → username → referral
- Clear errors (wrong code / offline)
- Notification shell ready

## Phase 2 — User approved + hide + persistent notif ✅
- You are approved + Go back
- Div scanner is running 24/7
- Notification tap → popup
- Launcher hide after approve

## Phase 3 — User hard scan upload ✅
- Passive signals package/build/root
- POST /v1/player/scan/run
- Quiet background, no spam UI

## Phase 4 — Owner register + wait approval ✅
- Register only (no login loop)
- Wait for admin screen
- Server truth on resume

## Phase 5 — Owner dashboard + referral ✅
- Big referral code + copy
- Empty players state
- Pull refresh status

## Phase 6 — Owner players + scores ✅
- Player list cards
- Last score / verdict badges
- Player detail + txt label

## Phase 7 — Admin owners board ✅
- Pending / approved boxes
- Approve / Remove
- Exclude admin from lists

## Phase 8 — Admin server health board ✅
- 9 service dots
- Wake/ping button
- Uptime snapshot

## Phase 9 — Admin scan feed ✅
- Latest scans stream
- Filter by verdict
- Owner/player link

## Phase 10 — Hard scan engine polish ✅
- deep_v3_hard banks
- Thresholds + findings cap
- Artifact .txt stable

## Phase 11 — AI heavy triage ✅
- High score → GitHub job
- Short summary to owner
- No raw secret leak

## Phase 12 — Mail + lock messages ✅
- HTML email on remove/approve
- Owner lock panel message
- SMTP via div-mail

## Phase 13 — Security hardening ✅
- Rate limits, JWT roles
- Player token scope
- Audit log basics

## Phase 14 — Design system pass
- Shared colors/type
- Empty/loading/error states
- Mobile admin CSS

## Phase 15 — E2E verify + keep-alive
- Full matrix test
- Termux keep-alive
- Release APKs

## Phase 16 — Freeze + docs
- Final URLs, passwords note
- Phase checklist
- No-demo production flag
