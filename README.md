# syncaxis-iam — project reference

Quick-orientation doc for coming back to this project later. For execution-ready instructions meant to be fed into a Claude Code session, see the three `*-integration-instructions.md` files below instead — this one is just for you.

## What this is

A centralized identity & access management service for Syncaxis's internal apps (Company Portal, Leads Tracker, ERP Dashboard, and any future app). One login, one place to manage users/roles/permissions, fine-grained per-action access control (`app.module.action` keys), SSO across apps via a short-lived code handoff — no shared cookie domain, no per-app credential distribution.

Full design rationale is in **`syncaxis-iam-architecture.md`** (also exported as `.docx`/`.pdf`) — read that first if you need the *why*, not just the *what*.

## Current status (as of 2026-09-16)

- ✅ Service built, running, and smoke-tested locally (`service/`) — TypeScript/Express, full auth API + admin JSON API + server-rendered admin console.
- ✅ `AuthCenter` database created locally (`SYNCAXIS_AUTHCENTER` on `localhost\SQLEXPRESS`, via the scripts in `db/`).
- ✅ Portal's 18 users, 3 roles, 1 group, and 21 legacy permission grants migrated into `AuthCenter` (translated into 13 proper `portal.*` permission keys).
- ✅ Leads Tracker's `leads` app pre-registered with 10 permission keys (`leads.leads.*`, `leads.customers.*`, `leads.admin.manage`).
- ✅ ERP Dashboard's `erp` app pre-registered with 3 permission keys (`erp.dashboard.sales.view`, `.finance.view`, `.finance.export`) — its instructions doc adds 6 more to match its actual report sections.
- ✅ Integration instructions written for all three consuming apps (Portal, Leads Tracker, ERP Dashboard) — none yet executed in those repos.
- ✅ Pushed to GitHub: `https://github.com/ashishpatelnx5/syncaxis-iam-app.git` (branch `main`).
- ⬜ Portal not yet cut over to actually call `syncaxis-iam`.
- ⬜ Leads Tracker not yet cut over.
- ⬜ ERP Dashboard not yet cut over.
- ⬜ No production deployment — everything so far is `localhost` only.

## Folder guide

```
syncaxis-iam/
  syncaxis-iam-architecture.md/.docx/.pdf   Full architecture & requirements (16 sections + appendix)
  portal-integration-instructions.md        Feed this into a Claude session in syncaxis-company-portal
  leads-integration-instructions.md         Feed this into a Claude session in Syncaxis_Leads_app
  erp-dashboard-integration-instructions.md Feed this into a Claude session in Syncaxis_ERP_Dashboard
  README.md                                 This file
  db/
    01-syncaxis-iam-create-db.sql            Creates the SYNCAXIS_AUTHCENTER database
    02-syncaxis-iam-schema.sql                Tables + seed roles/apps/permissions
    03-syncaxis-iam-create-login.sql          Creates the service's SQL login (password redacted — see below)
  service/                                  The actual syncaxis-iam Node/TypeScript service
    src/                                     API + admin console source
    scripts/seed.ts                          Bootstrap/reset the first admin user
    scripts/migrate-portal-users.ts           One-time Portal → AuthCenter data migration (already run)
    .env.example                              Template — copy to .env, fill in real values (.env is gitignored)
  migration-output/                         Portal user↔employee ID mapping (gitignored — real usernames)
```

## Running it locally

```
cd service
npm install
npm run dev          # http://localhost:8054
```

Admin console: `http://localhost:8054/admin-ui` (redirects to login automatically).
Local bootstrap admin: username `admin`, password `ChangeMe@2026` — **change this** if this ever stops being a throwaway local instance.

`db/03-syncaxis-iam-create-login.sql` has its password redacted (`CHANGE_ME_STRONG_PASSWORD`) before it went to GitHub — the real one used locally lives only in `service/.env` (gitignored, never committed).

## The three integration documents — what they're for

All are **written for a Claude Code session running inside that other repo**, not for you to execute directly here. Copy the full file contents into a new session opened at that project.

- **`portal-integration-instructions.md`** — Company Portal. Recommends a facade pattern (Portal keeps its exact current API shape, swaps the implementation underneath to delegate to `syncaxis-iam`) so Leads Tracker and ERP Dashboard don't break mid-migration. Includes a later, separately-gated phase to fully decommission Portal's own user/role management (code + database), once the facade is proven solid.
- **`leads-integration-instructions.md`** — Leads Tracker. Retargets its existing Portal-proxy pattern to `syncaxis-iam` directly, and adds real per-action permission enforcement (view/create/update/delete/export) using the 10 already-registered `leads.*` keys, replacing today's single blanket admin check.
- **`erp-dashboard-integration-instructions.md`** — ERP Dashboard. Same retargeting as Leads Tracker (it already had an identical Portal-proxy pattern, copied from Leads Tracker's own code per its comments), but adds *the first* per-section permission split this app has ever had — today every report (Sales, Finance, Purchase, etc.) is open to any logged-in user with no distinction. Flags one open decision: what to do with the app's existing shared/no-identity fallback login.

**Sequencing matters for both Leads Tracker and ERP Dashboard**: their SSO-from-Portal requirement depends on Portal's migration being live first (or simultaneous) — each doc explains why in its own §2.

## Next steps, in order

1. Feed `portal-integration-instructions.md` to a Claude session in `syncaxis-company-portal`, implement, test against its own checklist.
2. Feed `leads-integration-instructions.md` to a Claude session in `Syncaxis_Leads_app` — only after step 1 is confirmed working.
3. Feed `erp-dashboard-integration-instructions.md` to a Claude session in `Syncaxis_ERP_Dashboard` — same precondition as step 2.
4. Decide on a real deployment target for `syncaxis-iam` itself (currently `localhost` only) — needed before any of the above can point at anything but a dev machine.
5. Once all three apps are confirmed stable on `syncaxis-iam`, revisit Portal's decommission phase (§8 of its instructions doc) to remove the now-redundant `portal.Users`/`Roles`/etc.
