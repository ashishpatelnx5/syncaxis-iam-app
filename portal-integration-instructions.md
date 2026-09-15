# Integrating Company Portal with syncaxis-iam — requirements & instructions

**Written for:** a Claude Code session (and developer) working directly inside `F:\Workspace\syncaxis-company-portal`. This document is self-contained — it does not assume you have access to the `syncaxis-iam` project or its conversation history.

**Hard constraint:** everything in this document is implemented **inside `syncaxis-company-portal` only**. Nothing here requires touching `F:\Workspace\syncaxis-iam` — if something seems to need a change there (e.g. a missing permission key), the fix is an API call (`POST /admin/apps/portal/permissions`, documented below), never a direct edit to that project's files or database.

**This document includes an irreversible database step (§8).** Do not run §8.3's `DROP TABLE` script until every item in §9's testing checklist passes against the new integration. If you are the Claude Code session executing this and you are not fully confident that checklist passes, stop and confirm with the user before running it — don't proceed on your own judgement for a step that can't be undone.

---

## 1. What this is

`syncaxis-iam` is a new, already-built, already-running centralized identity/access-control service. It owns user accounts, passwords, roles, and permissions in its own database (`AuthCenter`) — Portal is meant to stop being its own identity authority and become a **consumer** of this service instead, the same way Leads Tracker already consumes Portal's auth endpoints today.

**Base URL (local dev):** `http://localhost:8054`
**Health check:** `GET http://localhost:8054/health` → `{"ok":true,"db":"connected"}`

There is no production URL yet — `syncaxis-iam` has only been run locally so far. Use an `IAM_API_URL` env var (see §5) so this is a one-line change later, exactly like Leads Tracker already does with `PORTAL_API_URL`.

## 2. What already happened (don't redo this)

Portal's existing identity data has already been **copied** (not moved) into `AuthCenter`:

- All 18 `portal.Users` rows → `AuthCenter.Users`, bcrypt password hashes carried over unchanged (no forced resets). Portal never collected email addresses, so each got a placeholder: `<username>@syncaxis.com`.
- All 3 `portal.Roles` (`Admin`, `Legacy - syncaxis`, `Sales & Marketing`) → `AuthCenter.Roles`, plus their `UserRoles`, `UserGroups`, `UserGroupMembers`, and `GroupRoles` assignments.
- All 21 `portal.RolePermissions` rows (the old `(ResourceType, ResourceKey)` flags, e.g. `('page','directory')`, `('application','leads-tracker')`) were translated into 13 proper permission keys under a `portal` app registered in `AuthCenter`, and re-granted to the equivalent roles. Full current list:

  ```
  portal.admin.users.manage        (stray pre-existing seed key — likely unused, verify before relying on it)
  portal.admin-complaints.manage
  portal.admin-leads-tracker.manage
  portal.applications.view
  portal.complaints.view
  portal.directory.view
  portal.erp.access
  portal.erp-dashboard.access
  portal.greythr.access
  portal.hierarchy.view
  portal.inquiry.access
  portal.leads-tracker.access
  portal.webmail.access
  ```

- **`portal.Users` and friends have NOT been deleted or modified yet.** Portal's own database is still fully functional as a fallback for now — this migration was additive only, so far. §8 of this document changes that, but only after the new integration is proven solid.
- A mapping report (old `portal.UserId` → new `AuthCenter UserId` → `EmployeeId`) was written to `F:\Workspace\syncaxis-iam\migration-output\portal-user-employee-mapping.json` (18 rows) — this is what §6.5 uses to preserve the employee linkage before `portal.Users` goes away.

**Known gap to verify:** Portal's `app/src/data/permissions.js` (`pagePermissions`) lists 14 page keys, but only 6 currently have any role grants recorded (and therefore got migrated): `directory`, `hierarchy`, `applications`, `complaints`, `admin-complaints`, `admin-leads-tracker`. The other 8 (`holidays`, `job-descriptions`, `daily-plan`, `admin-employees`, `admin-departments`, `admin-job-descriptions`, `admin-daily-plans`, `admin-holidays`) have no grants yet and so have no permission key registered in `AuthCenter` either. Similarly, `app/src/data/apps.js` currently lists 5 application tiles (`webmail`, `erp`, `erp-dashboard`, `greythr`, `inquiry`), but the old `RolePermissions` table also had grants for a 6th key, `leads-tracker`, that doesn't appear in `apps.js` as read — reconcile this (it may be legacy, or `apps.js` may have changed since). **Register the full, current manifest** (§6.4) rather than relying only on what happened to have grants already.

## 3. The critical sequencing risk — read this before writing any code

**Portal is not just its own identity provider today — it's also the identity provider for Leads Tracker and the ERP Dashboard.** Both of those apps already proxy their own login (`POST /api/auth/login`) and SSO handoff (`POST /api/auth/sso/exchange`) to **Portal's** backend, server-to-server, and periodically re-verify sessions against **Portal's** `GET /api/auth/me`.

If Portal's `/api/auth/*` routes are ripped out and replaced with direct calls to `syncaxis-iam`, and Leads/ERP are *not* touched in the same change, **Leads Tracker and ERP Dashboard will break** — their backends will keep calling Portal's endpoints, expecting Portal to still be the authority.

### Recommended approach: keep Portal's existing API surface as a facade

Don't change Portal's public contract at all — same URLs (`/api/auth/login`, `/api/auth/sso/issue`, `/api/auth/sso/exchange`, `/api/auth/me`, `/api/auth/change-password`), same request/response shapes. Only change what's *behind* those routes: instead of querying `portal.Users`/`portal.Roles` directly, they delegate to `syncaxis-iam`.

This means:
- **Zero changes needed to Leads Tracker or ERP Dashboard** — they keep calling Portal exactly as before; Portal is now a thin, transparent proxy in front of `syncaxis-iam`.
- **Zero (or near-zero) changes needed to Portal's own frontend** — `AuthContext.jsx`, `api.js`, `RequireAuth.jsx`, `Login.jsx` don't need to know anything changed, provided the response shape is preserved (§7 has the exact translation needed).
- Portal's own `portal.Users`/`Roles`/`RolePermissions` tables stop being read for auth decisions immediately, but stay in place until §8's decommission phase.

This is the approach the rest of this document assumes. If you'd rather cut Leads/ERP over to call `syncaxis-iam` directly in the same change (removing the proxy hop), that's a legitimate alternative — just be aware it triples the blast radius of this change, since it now touches three codebases instead of one.

## 4. syncaxis-iam API contract (authoritative — verified against the running service)

All calls are server-to-server (Portal's backend → `syncaxis-iam`), never from the browser directly.

**`POST {IAM_API_URL}/auth/login`**
Request: `{ "username": string, "password": string }`
Response `200`: `{ "token": string, "user": UserSummary }`
Errors: `400` (missing fields), `401` (bad credentials), `423` (account locked)

**`UserSummary`** shape (returned by login, sso/exchange, and me):
```json
{
  "id": 1,
  "username": "mahesh.babar",
  "displayName": "Mahesh Babar",
  "isActive": true,
  "roles": [{ "id": 1, "name": "Admin" }],
  "perms": ["portal.directory.view", "portal.hierarchy.view", "..."],
  "isFullAccess": false,
  "lastLoginAt": "2026-09-15T11:11:28.478Z"
}
```

**`POST {IAM_API_URL}/auth/sso/issue`** — `Authorization: Bearer <iamToken>` required
Response `200`: `{ "code": string }` — single-use, 60-second TTL

**`POST {IAM_API_URL}/auth/sso/exchange`**
Request: `{ "code": string }`
Response `200`: `{ "token": string, "user": UserSummary }`
Error `401`: expired/invalid code

**`GET {IAM_API_URL}/auth/me`** — `Authorization: Bearer <iamToken>` required
Response `200`: `{ "user": UserSummary }`
Error `401`: token invalid, user deactivated, or revoked (password changed / force-logout elsewhere)

**`POST {IAM_API_URL}/auth/change-password`** — `Authorization: Bearer <iamToken>` required
Request: `{ "currentPassword": string, "newPassword": string }` (new password ≥ 8 chars)
Response: `204`
Errors: `400`, `401` (wrong current password)

**`POST {IAM_API_URL}/auth/logout`** — `Authorization: Bearer <iamToken>` required. `204`, mainly for symmetry/audit.

No CORS is configured on `syncaxis-iam` — by design, nothing is meant to call it directly from a browser. All calls above must originate from Portal's backend.

## 5. Config changes

Add to `app/server/.env` (and `.env.example`):
```
IAM_API_URL=http://localhost:8054
```

`JWT_SECRET` in Portal's own `.env` stays — Portal will still self-sign a short-lived session token for its **own** frontend (see §6), it just stops being the thing that authenticates a password. Nothing else in `.env` needs to change.

## 6. Backend changes — the core of this migration

**Reference implementation to copy the pattern from:** `F:\Workspace\Syncaxis_Leads_app\app\server\src\auth.ts` and `app/server/src/routes/auth.ts` in that same repo. Leads Tracker already does exactly this — proxies login/SSO to an external identity API, keeps its own local session, periodically re-verifies — just pointed at Portal instead of `syncaxis-iam`, and written in TypeScript instead of Portal's plain JS. Read those two files first; the code below adapts the same pattern to Portal's stack (plain ESM JS, `mssql`, `jsonwebtoken`, `bcryptjs` already in `package.json`).

### 6.1 `app/server/src/middleware/auth.js` — replace the body, keep the shape

Today, `requireAuth` verifies a Portal-signed JWT locally, and `getEffectiveAccess`/`requirePermission` query `portal.Roles`/`portal.RolePermissions` directly. Replace this with:

- `requireAuth` still verifies Portal's own locally-signed JWT (unchanged — this token never leaves Portal, it's what Portal's *own* frontend holds, exactly as today).
- After verifying the local JWT, look up an in-memory session record (keyed by the JWT's user id, or a session id embedded in it) that holds the **iam-issued token** obtained at login/SSO time.
- Re-verify that session against `syncaxis-iam`'s `GET /auth/me` no more often than every 5 minutes (mirror Leads' `reverifyWithPortal` → rename conceptually to `reverifyWithIam`) — cache the resolved `perms`/`isFullAccess` on the session between re-verifies.
- `getEffectiveAccess` becomes: read `perms`/`isFullAccess` off that cached session record, then run the translation in §6.3 to produce Portal's existing `{ pages: Set, applications: Set, isAdmin: boolean, roles }` shape — same output shape the rest of the codebase (route files, `req.user` consumers) already expects, so nothing downstream needs to change.
- `requirePermission`/`requireAdmin` stay as-is — they already just consult whatever `getEffectiveAccess` returns.

### 6.2 `app/server/src/routes/auth.js` — replace the body, keep the routes

- **`POST /login`**: instead of querying `portal.Users` + `bcrypt.compare`, `fetch(IAM_API_URL + '/auth/login', ...)` with the posted credentials. On success, create Portal's own local session (mirrors Leads' `establishSession`): store the iam token + `perms`/`isFullAccess` server-side, mint Portal's own JWT for the browser exactly as today, and return `{ token, user }` in Portal's existing shape (§6.3 translation).
- **`POST /sso/issue`**: use the *current* Portal-authenticated user's stored iam token to call `syncaxis-iam`'s `POST /auth/sso/issue`, and return that code as-is. (Portal's frontend/`AppCard.jsx` doesn't need to change — it already just relays whatever code this endpoint returns.)
- **`POST /sso/exchange`**: called server-to-server by Leads/ERP today, expecting Portal to mint a session. Now: call `syncaxis-iam`'s `POST /auth/sso/exchange` with the same code, translate the response, and return `{ token, user }` in Portal's existing shape — Leads/ERP never notice the difference.
- **`GET /me`**: read from the current session (re-verifying via the 5-minute cadence in §6.1 if due), translate, return.
- **`POST /change-password`**: proxy to `syncaxis-iam`'s `POST /auth/change-password` with the bearer being the session's stored iam token. On success, Portal's existing behavior (re-sign a fresh local JWT so the current browser session doesn't get logged out mid-flow — see the "stayed logged in across a password change" note the `syncaxis-iam` project already solved this exact problem for its own admin console; copy that same fix here) should still apply.
- **`POST /logout`**: keep clearing Portal's local session; optionally also call `syncaxis-iam`'s `/auth/logout` for symmetry (not required).

### 6.3 The permission-translation function (exact spec — this is the one new piece of logic)

`syncaxis-iam` returns a flat `perms: string[]` of `portal.<resourceKey>.<action>` keys and one `isFullAccess: boolean`. Portal's existing code (frontend `AuthContext.jsx`'s `hasPage`/`hasApp`, and any backend route using `pages`/`applications`) expects `{ pages: string[], applications: string[], isAdmin: boolean }`. Convert with:

```js
const PORTAL_PERM = /^portal\.([a-z0-9-]+)\.(view|manage|access)$/;

function accessFromIamUser(iamUser) {
  const pages = [];
  const applications = [];
  for (const key of iamUser.perms) {
    const match = key.match(PORTAL_PERM);
    if (!match) continue; // ignore keys belonging to other apps, if any ever appear here
    const [, resourceKey, action] = match;
    if (action === 'access') applications.push(resourceKey);
    else pages.push(resourceKey); // 'view' or 'manage'
  }
  return { pages, applications, isAdmin: iamUser.isFullAccess };
}
```

This is the exact inverse of how the migration (§2) built these keys, so it round-trips correctly against every currently-migrated permission.

### 6.4 Register Portal's full permission manifest with syncaxis-iam

Call this once (e.g. from a small script, or on Portal server startup — see `syncaxis-iam`'s own apps' pattern of self-registering on every boot, §8.3 of its architecture doc) so every page/tile Portal actually has — not just the ones that happened to have grants already — shows up in `syncaxis-iam`'s admin permission matrix:

```
POST {IAM_API_URL}/admin/apps/portal/permissions
Authorization: Bearer <a syncaxis-iam token for a user holding iam.admin.manage>
Content-Type: application/json

{
  "permissions": [
    { "key": "portal.directory.view", "description": "View Portal's directory page" },
    { "key": "portal.hierarchy.view", "description": "View Portal's org chart" },
    { "key": "portal.applications.view", "description": "View Portal's Applications page" },
    { "key": "portal.holidays.view", "description": "View Portal's Holidays page" },
    { "key": "portal.job-descriptions.view", "description": "View Portal's Job Descriptions page" },
    { "key": "portal.daily-plan.view", "description": "View Portal's Daily Plan page" },
    { "key": "portal.complaints.view", "description": "View Portal's Complaints & Feedback page" },
    { "key": "portal.admin-employees.manage", "description": "Manage employees" },
    { "key": "portal.admin-departments.manage", "description": "Manage departments" },
    { "key": "portal.admin-job-descriptions.manage", "description": "Manage job descriptions" },
    { "key": "portal.admin-daily-plans.manage", "description": "Manage team daily plans" },
    { "key": "portal.admin-holidays.manage", "description": "Manage holidays" },
    { "key": "portal.admin-complaints.manage", "description": "Manage complaints & feedback" },
    { "key": "portal.admin-leads-tracker.manage", "description": "Manage Leads Tracker admin section" },
    { "key": "portal.webmail.access", "description": "Access the Webmail tile" },
    { "key": "portal.erp.access", "description": "Access the ERP tile" },
    { "key": "portal.erp-dashboard.access", "description": "Access the ERP Dashboard tile (SSO)" },
    { "key": "portal.greythr.access", "description": "Access the GreytHR tile" },
    { "key": "portal.inquiry.access", "description": "Access the Enquiry Portal tile (SSO)" }
  ]
}
```
This call is idempotent — safe to run every startup. Cross-check this list against the current `app/src/data/permissions.js` and `app/src/data/apps.js` before sending it, since those are the real source of truth for what pages/tiles currently exist, and resolve the `leads-tracker` discrepancy noted in §2 while you're there.

### 6.5 The `EmployeeId` linkage — requires one additive schema change to `portal.Employees`

Portal's current `toUserSummary` includes `employeeId: user.EmployeeId`, read today from `portal.Users`. Because `portal.Users` is being dropped in §8, this needs a permanent home that survives that — on `portal.Employees` itself, not on the identity table.

**Do this now, before §8, while `portal.Users` still exists:**

1. Add a column:
   ```sql
   ALTER TABLE portal.Employees ADD AuthUserId INT NULL;
   ```
   (Plain nullable column, no cross-database foreign key — `AuthCenter` may live on a different server in production, so this is an application-level reference, not an enforced one.)

2. Backfill it from the mapping file already produced during the `AuthCenter` migration: `F:\Workspace\syncaxis-iam\migration-output\portal-user-employee-mapping.json` (18 rows: `{ portalUserId, username, authCenterUserId, employeeId }`). For every row where `employeeId` is not null, run:
   ```sql
   UPDATE portal.Employees SET AuthUserId = <authCenterUserId> WHERE EmployeeId = <employeeId>;
   ```
   (Write a tiny script that reads the JSON file and generates/executes these — 18 rows, trivial either way.)

3. Update the login/sso-exchange handlers (§6.2) to resolve `employeeId` like this instead of querying `portal.Users`:
   ```sql
   SELECT EmployeeId FROM portal.Employees WHERE AuthUserId = @iamUserId
   ```
   using `user.id` from the `syncaxis-iam` `UserSummary` (§4) as `@iamUserId`.

**Note for later:** any user created going forward via `syncaxis-iam`'s own admin console (not Portal's, per §8) won't automatically get an `AuthUserId` link on `portal.Employees` — nothing in this design wires that up automatically anymore, since account creation moved off Portal. If that link matters operationally, it needs a manual step (or a small future tool) when onboarding a new employee: set `AuthUserId` on their `Employees` row once their `syncaxis-iam` account exists.

## 7. Frontend changes

If §6.3's translation is implemented correctly, **`app/src/context/AuthContext.jsx`, `app/src/utils/api.js`, `app/src/components/RequireAuth.jsx`, and `app/src/pages/Login.jsx` should need no changes at all** — they already only consume `{ token, user: { id, username, displayName, isAdmin, roles, lastLoginAt, permissions: { pages, applications } } }`, which is exactly what the backend continues to return.

Verify this assumption by testing login, page-permission gating (`hasPage`), and app-tile gating (`hasApp`) end-to-end after the backend changes — don't assume, confirm.

## 8. Decommission Portal's own user/role management — code and database

**Gate: do not start this section until §6 and §7 are complete and every item in §9's testing checklist passes**, including the `AuthUserId`-based employee lookup from §6.5. This section removes the code and drops the database tables that back Portal's own user/role/group management — once §8.3 runs, there is no "just revert the code" fallback anymore, only the backup taken in §8.2.

**Verified before writing this section:** no other table in Portal's `portal` schema has a foreign key, or an obvious soft reference (a `CreatedBy`/`OwnerId`-style column), pointing at `Users`, `Roles`, `UserRoles`, `UserGroups`, `UserGroupMembers`, or `GroupRoles`/`RolePermissions` — confirmed via `sys.foreign_keys` and a column-name sweep across every other table in the schema. The identity subsystem is fully self-contained in those seven tables; dropping them doesn't orphan anything else in Portal's database.

### 8.1 Code to remove

- `app/server/src/routes/users.js`, `roles.js`, `userGroups.js` — delete. Remove their mounts in `app/server/src/app.js` (the `app.use('/api/users', ...)`, `/api/roles`, `/api/user-groups` lines).
- `app/src/pages/UsersAdmin.jsx`, `RolesAdmin.jsx`, `UserGroupsAdmin.jsx` — delete.
- `app/src/components/UserForm.jsx`, `RoleForm.jsx`, `UserGroupForm.jsx` — delete, after confirming with a search that nothing else imports them.
- Remove these pages' routes from Portal's frontend router and their entries from the nav — search the codebase for where they're wired in (likely `App.jsx` and `Layout.jsx`, but confirm rather than assume).
- Add a link to `syncaxis-iam`'s own admin console (wherever it ends up hosted) somewhere in Portal's admin/settings area, so admins have an obvious path to real user/role management going forward.

Run this first and follow every hit — treat the file list above as a starting point, not a guarantee of completeness, since it's based on a partial read of the codebase:
```
grep -rn "UsersAdmin\|RolesAdmin\|UserGroupsAdmin\|UserForm\|RoleForm\|UserGroupForm\|/api/users\|/api/roles\|/api/user-groups" app/src app/server/src
```

### 8.2 Back up before dropping anything

```sql
USE SYNCAXIS_PORTAL;
GO
CREATE SCHEMA portal_backup_pre_iam_cutover;
GO
SELECT * INTO portal_backup_pre_iam_cutover.Users FROM portal.Users;
SELECT * INTO portal_backup_pre_iam_cutover.Roles FROM portal.Roles;
SELECT * INTO portal_backup_pre_iam_cutover.UserRoles FROM portal.UserRoles;
SELECT * INTO portal_backup_pre_iam_cutover.UserGroups FROM portal.UserGroups;
SELECT * INTO portal_backup_pre_iam_cutover.UserGroupMembers FROM portal.UserGroupMembers;
SELECT * INTO portal_backup_pre_iam_cutover.GroupRoles FROM portal.GroupRoles;
SELECT * INTO portal_backup_pre_iam_cutover.RolePermissions FROM portal.RolePermissions;
GO
```
Keep this backup schema for at least a few weeks after cutover — don't drop it in the same sitting as §8.3.

### 8.3 Drop the tables

Dependency-safe order — children before parents, verified against `sys.foreign_keys` (§8 intro):

```sql
USE SYNCAXIS_PORTAL;
GO
DROP TABLE IF EXISTS portal.RolePermissions;
DROP TABLE IF EXISTS portal.GroupRoles;
DROP TABLE IF EXISTS portal.UserGroupMembers;
DROP TABLE IF EXISTS portal.UserRoles;
DROP TABLE IF EXISTS portal.UserGroups;
DROP TABLE IF EXISTS portal.Roles;
DROP TABLE IF EXISTS portal.Users;
GO
```

### 8.4 Verify after dropping

- [ ] Portal starts cleanly (`npm run dev` / `npm start` in `app/server`) with no errors about missing tables.
- [ ] Login, page-permission gating, app-tile SSO, and the Employee Directory (now using `Employees.AuthUserId` instead of `Users.EmployeeId`) all still work.
- [ ] `grep -rn "portal.Users\|portal.Roles\|portal.UserRoles\|portal.UserGroups\|portal.GroupRoles\|portal.RolePermissions" app/server/src` returns nothing — confirms no leftover code still queries the dropped tables.

## 9. Testing checklist (before §8)

- [ ] Login via Portal's UI with a real migrated account (e.g. `mahesh.babar`) — same password as before, no reset needed.
- [ ] `hasPage`/`hasApp` gating still shows/hides the same nav items as before migration, for at least one non-admin and one admin account.
- [ ] Click an SSO-enabled app tile (ERP Dashboard or the Enquiry/Leads Tracker tile) from Portal — confirm it still lands the user already signed in, with **zero changes to those apps' own code**.
- [ ] Change password via Portal's own change-password UI — confirm the current session doesn't get logged out mid-flow, and the new password works on next login.
- [ ] Deactivate or lock a user via `syncaxis-iam`'s admin console — confirm that user is rejected on their next Portal login attempt (and, within 5 minutes, on their next request if already signed in).
- [ ] Grant/revoke a permission via `syncaxis-iam`'s permission matrix for the `portal` app — confirm it's reflected in Portal within 5 minutes (or immediately after a fresh login).
- [ ] `employeeId` still resolves correctly after switching to the `AuthUserId`-based lookup (§6.5) — spot-check a few migrated accounts against `portal-user-employee-mapping.json`.
- [ ] Confirm `portal.Users`/`Roles`/`RolePermissions` (still present at this point) were not written to by any of the above.

## 10. Rollback

**Before §8 runs:** keep the old, `portal.Users`-backed auth code path available behind a feature flag (an env var like `AUTH_SOURCE=iam|local`) until §9 is confirmed solid, rather than deleting it immediately.

**After §8.3 runs:** there is no code-level rollback anymore — the tables are gone. Recovery at that point means restoring from `portal_backup_pre_iam_cutover` (§8.2) or a full database backup, and reverting the code changes from §6–§8.1 via git. This is exactly why §8's gate exists — don't reach this step until you don't need the rollback.

## 11. Open questions for whoever executes this (not decidable from this document alone)

1. Resolve the `leads-tracker` vs. `apps.js` discrepancy noted in §2 before finalizing the permission manifest in §6.4.
2. `IAM_API_URL` for any non-local environment — `syncaxis-iam` hasn't been deployed anywhere but localhost yet, so this will need to be revisited once it has a real address.
3. How long to retain `portal_backup_pre_iam_cutover` (§8.2) before it's safe to drop too.
4. Who is responsible for setting `Employees.AuthUserId` when a new employee's `syncaxis-iam` account is created going forward (§6.5's "note for later") — this is a process gap this migration introduces, not something the code alone solves.
5. Whether to eventually migrate Leads Tracker/ERP Dashboard to call `syncaxis-iam` directly (removing Portal as a proxy hop) — optional, not required for this change, and out of scope for this document since it touches other repositories.
