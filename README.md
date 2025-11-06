# secure-api babdessamadAA

Secure Node.js/Express API with:
- JWT authentication
- Role-based access control (`admin` vs `user`)
- Input validation (`express-validator`)
- SQLite for persistence

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Configure environament:
   - Create `.env` with:
     - `JWT_SECRET=<your-secret>`
     - Optional: `JWT_EXPIRES_IN=900` (seconds)
     - Optional: `NVD_API_KEY=<your-nvd-api-key>`

3. Run the server:
   ```bash
   npm run dev
   # or
   npm start
   ```

## Docker Deployment

1. Build and run with Docker Compose:
   ```bash
   # From project root (where docker-compose.yml lives)
   docker compose up -d --build
   ```

2. Environment variables (recommended to set in your shell or a .env file at project root):
   - `JWT_SECRET` (required)
   - `JWT_EXPIRES_IN` (optional, default `900`)
   - `ALLOWED_ORIGINS` (comma-separated origins for CORS)
   - `JSON_BODY_LIMIT`, `FORM_BODY_LIMIT` (body size limits)
   - `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX` (global limiter)
   - `AUTH_RATE_LIMIT_WINDOW_MS`, `AUTH_RATE_LIMIT_MAX` (auth limiter)
   - `NVD_API_KEY` (optional for NVD quotas)

3. SQLite persistence:
   - The DB file is stored in the named volume `secure_api_sqlite_data` mounted at `/data/data.sqlite` inside the container.
   - To inspect: `docker exec -it secure-api sh` then `sqlite3 /data/data.sqlite`.

4. Healthcheck:
   - `GET /health` is used by Docker to monitor the container.

5. Logs:
   - `docker compose logs -f secure-api`

## Health

- `GET /health` — returns `{ status: "ok" }` (public)

## Auth

- `POST /api/register` (public)
  - Body: `{ "username", "email", "password", "role"? }`
  - Creates user (default role `user`).

- `POST /api/login` (public)
  - Body: `{ "username", "password" }`
  - Returns: `{ access_token, token_type: "Bearer", expires_in }`.

- `GET /api/profile` (auth)
  - Header: `Authorization: Bearer <token>`
  - Returns current user: `{ id, username, email, role }`.

- `GET /api/users` (admin)
  - List users with pagination.
  - Query: `page` (default 1), `limit` (default 50, max 200)
  - Returns: `{ page, limit, count, total_count, has_next, items }`.

- `DELETE /api/users/:id` (admin)
  - Delete a user by id.
  - Optional: `?cascade=true` to also delete all resources owned by that user.

- `DELETE /api/users/by-username/:username` (admin)
  - Delete a user by username.

## Resources (generic)

- `GET /api/resources` (auth)
  - List resources for the current user (admin sees all).
  - Query: `type`, `q`, `page`, `limit`
  - Returns: `{ page, limit, count, items }`.

- `POST /api/resources` (auth)
  - Body: `{ "name", "type"?, "metadata"? }` — creates resource owned by the user.

- `PATCH /api/resources/:id` (auth)
  - Owner or admin can update name/type/metadata.

- `DELETE /api/resources/:id` (auth)
  - Owner or admin can delete.

## CVE (stored)

- `GET /api/cves` (auth)
  - List CVEs with filters and pagination.
  - Query: `cve_id` (exact, case-insensitive), `severity` (exact), `q` (text)
  - Returns: `{ page, limit, count, total_count, has_next, items }`.

- `GET /api/cves/:id` (auth)
  - Detail by numeric ID (stored record).
  - `description_html` is sanitized server-side to prevent XSS.

- `GET /api/cves/by-id/:cve_id` (auth)
  - Detail by `cve_id` (e.g. `CVE-2021-4193`).
  - `description_html` is sanitized server-side.

- `POST /api/cves` (admin)
  - Body: `{ cve_id, title, description, severity, cvss_score?, affected_products?, references?, recommendation?, published_at?, last_modified? }`
  - Creates CVE; prevents duplicates; normalizes `references`.

- `PATCH /api/cves/:id` (admin)
  - Updates CVE; normalizes `references` on write.

- `DELETE /api/cves/:id` (admin)
  - Deletes CVE.

## CVE (external integrations)

- `GET /api/cves/nvd/:cve_id` (auth)
  - Live NVD lookup (no storage). References sanitized in response.
  - `description_html` is sanitized server-side.

- `GET /api/cves/:cve_id/external` (auth)
  - Live CVE.org lookup (no storage). References sanitized in response.
  - `description_html` is sanitized server-side.

- `POST /api/cves/import` (admin)
  - Body: `{ cve_id }`
  - Imports and stores CVE from CVE.org; normalizes `references`.

- `POST /api/cves/sync` (admin)
  - Body: `{ cve_id }`
  - Upserts CVE from CVE.org; normalizes `references`.

- `POST /api/cves/import-bulk` (admin)
  - Body: `{ year? , pubStartDate? , pubEndDate? , resultsPerPage? , delayMs? }`
  - Imports CVEs from NVD across a period; chunking windows; respects NVD API limits; use `NVD_API_KEY` for higher quotas.

## CVE (references maintenance)

- `POST /api/cves/normalize` (admin)
  - Body: `{ dryRun?: boolean, limit?: number }`
  - Normalizes stored `references` (trim wrappers, deduplicate). Returns summary with counts.

- `POST /api/cves/normalize-force` (admin)
  - Body: `{ limit?: number }`
  - Forces normalization and writes back; useful if change detection fails.

## Environment

- `JWT_SECRET` (required): secret key for JWT.
- `JWT_EXPIRES_IN` (optional): seconds to expire (default `900`).
- `NVD_API_KEY` (optional): NVD API key for improved rate limits.
- `ALLOWED_ORIGINS` (optional): restrict CORS to trusted origins.
- `JSON_BODY_LIMIT`, `FORM_BODY_LIMIT` (optional): limit payload sizes.
- `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX` (optional): global rate limiter.
- `AUTH_RATE_LIMIT_WINDOW_MS`, `AUTH_RATE_LIMIT_MAX` (optional): auth rate limiter.

### Insecure Mode (no auth, no security)
- Set `DISABLE_AUTH=true` to bypass JWT and role checks (all routes act as admin, no token required).
- Set `DISABLE_SECURITY=true` to disable CORS restrictions, body size limits, and rate limiting.
- Restart the API after changing env.
- Example:
  ```bash
  export DISABLE_AUTH=true
  export DISABLE_SECURITY=true
  npm run dev
  # Now call routes WITHOUT Authorization header
  curl http://localhost:3000/api/users?page=1&limit=50
  curl http://localhost:3000/api/cves?page=1&limit=10
  ```

## Audit Logs

- Admin actions are recorded in table `audit_logs`:
  - Fields: `id`, `actor_id`, `action`, `entity_type`, `entity_id`, `details`, `created_at`.
  - Logged actions: `create_cve`, `delete_cve`, `import_cve`, `sync_cve`, `delete_user`.

## Curl Examples

```bash
# Register
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@example.com","password":"S3cur3P@ssw0rd","role":"admin"}'

# Login
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"S3cur3P@ssw0rd"}'

# Profile
curl http://localhost:3000/api/profile -H "Authorization: Bearer <token>"

# List users (admin)
curl "http://localhost:3000/api/users?page=1&limit=50" -H "Authorization: Bearer <token>"

# Delete user (admin)
curl -X DELETE http://localhost:3000/api/users/3 -H "Authorization: Bearer <token>"

# Delete user by username (admin)
curl -X DELETE http://localhost:3000/api/users/by-username/user2 -H "Authorization: Bearer <token>"

# List CVEs
curl "http://localhost:3000/api/cves?page=1&limit=10&severity=high" -H "Authorization: Bearer <token>"

# Live NVD
curl http://localhost:3000/api/cves/nvd/CVE-2021-4193 -H "Authorization: Bearer <token>"

# Import CVE (CVE.org)
curl -X POST http://localhost:3000/api/cves/import \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2021-4193"}'

# Bulk import (NVD by year)
curl -X POST http://localhost:3000/api/cves/import-bulk \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"year":2021,"resultsPerPage":2000,"delayMs":1500}'

# Normalize references (dry-run first)
curl -X POST http://localhost:3000/api/cves/normalize \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"dryRun":true,"limit":1000}'

# Normalize references (force write)
curl -X POST http://localhost:3000/api/cves/normalize-force \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"limit":1000}'

# Delete CVE (admin)
curl -X DELETE http://localhost:3000/api/cves/21956 -H "Authorization: Bearer <token>"
```

## Exemples cURL détaillés (toutes les routes)

```bash
# ===== AUTH =====

# Créer un utilisateur (role user par défaut)
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"user2","email":"user2@example.com","password":"MotDePasseFort123!"}'

# Créer un admin
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin2","email":"admin2@example.com","password":"MotDePasseFort123!","role":"admin"}'

# Login (username + password)
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"S3cur3P@ssw0rd"}'

# Profil (Bearer token)
curl http://localhost:3000/api/profile -H "Authorization: Bearer <token>"

# Liste des utilisateurs (admin)
curl "http://localhost:3000/api/users?page=1&limit=50" -H "Authorization: Bearer <token>"

# Supprimer utilisateur par id (admin)
curl -i -X DELETE http://localhost:3000/api/users/4 -H "Authorization: Bearer <token>"

# Supprimer utilisateur par username (admin)
curl -i -X DELETE http://localhost:3000/api/users/by-username/user2 -H "Authorization: Bearer <token>"

# Supprimer utilisateur avec cascade des ressources (admin)
curl -i -X DELETE "http://localhost:3000/api/users/4?cascade=true" -H "Authorization: Bearer <token>"

# ===== RESSOURCES GENERIQUES =====

# Liste des ressources (admin: tout; user: seulement ses ressources)
curl "http://localhost:3000/api/resources?page=1&limit=20&type=cve&q=vim" -H "Authorization: Bearer <token>"

# Créer une ressource générique
curl -X POST http://localhost:3000/api/resources \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"name":"my-note","type":"note","metadata":{"text":"hello"}}'

# Mettre à jour une ressource (name/type/metadata)
curl -X PATCH http://localhost:3000/api/resources/123 \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"name":"my-note-renamed","metadata":{"text":"updated"}}'

# Supprimer une ressource
curl -X DELETE http://localhost:3000/api/resources/123 -H "Authorization: Bearer <token>"

# ===== CVE STOCKEES =====

# Liste des CVE (filtres disponibles)
curl "http://localhost:3000/api/cves?page=1&limit=10" -H "Authorization: Bearer <token>"
curl "http://localhost:3000/api/cves?page=1&limit=10&severity=high" -H "Authorization: Bearer <token>"
curl "http://localhost:3000/api/cves?page=1&limit=10&cve_id=CVE-2021-4193" -H "Authorization: Bearer <token>"
curl "http://localhost:3000/api/cves?page=1&limit=10&q=vim" -H "Authorization: Bearer <token>"

# Détail par ID numérique
curl http://localhost:3000/api/cves/21956 -H "Authorization: Bearer <token>"

# Détail par cve_id
curl http://localhost:3000/api/cves/by-id/CVE-2021-4193 -H "Authorization: Bearer <token>"

# Créer une CVE (admin)
curl -X POST http://localhost:3000/api/cves \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{
    "cve_id":"CVE-2024-0001",
    "title":"Exemple CVE",
    "description":"Exemple",
    "severity":"high",
    "cvss_score":9.0,
    "affected_products":["vendor product version"],
    "references":["https://example.com/advisory"],
    "recommendation":"Appliquer les correctifs",
    "published_at":"2024-01-15T00:00:00Z",
    "last_modified":"2024-02-01T00:00:00Z",
    "description_html":"<p>Exemple <strong>HTML</strong></p>"
  }'

# Mettre à jour une CVE (admin)
curl -X PATCH http://localhost:3000/api/cves/21956 \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"severity":"medium","references":["https://example.com/new-advisory"]}'

# Supprimer une CVE (admin)
curl -X DELETE http://localhost:3000/api/cves/21956 -H "Authorization: Bearer <token>"

# ===== CVE EXTERNES & IMPORT =====

# Live NVD (sans stockage)
curl http://localhost:3000/api/cves/nvd/CVE-2021-4193 -H "Authorization: Bearer <token>"

# Live CVE.org (sans stockage)
curl http://localhost:3000/api/cves/CVE-2021-4193/external -H "Authorization: Bearer <token>"

# Import CVE (CVE.org)
curl -X POST http://localhost:3000/api/cves/import \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2021-4193"}'

# Sync CVE (upsert depuis CVE.org)
curl -X POST http://localhost:3000/api/cves/sync \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2021-4193"}'

# Import NVD en masse (par année)
curl -X POST http://localhost:3000/api/cves/import-bulk \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"year":2021,"resultsPerPage":2000,"delayMs":1500}'

# Import NVD en masse (par période ISO UTC)
curl -X POST http://localhost:3000/api/cves/import-bulk \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"pubStartDate":"2021-07-01T00:00:00Z","pubEndDate":"2021-07-15T23:59:59Z","resultsPerPage":2000,"delayMs":1500}'

# ===== NORMALISATION REFERENCES CVE =====

# Normaliser les références (dry-run)
curl -X POST http://localhost:3000/api/cves/normalize \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"dryRun":true,"limit":1000}'

# Normaliser les références (force write)
curl -X POST http://localhost:3000/api/cves/normalize-force \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"limit":1000}'
```

## Exemples cURL (mode insecure, sans token)

```bash
# Users
curl "http://localhost:3000/api/users?page=1&limit=50"
curl -i -X DELETE http://localhost:3000/api/users/3
curl -i -X DELETE "http://localhost:3000/api/users/3?cascade=true"

# Resources
curl "http://localhost:3000/api/resources?page=1&limit=20&type=cve&q=vim"
curl -X POST http://localhost:3000/api/resources -H "Content-Type: application/json" -d '{"name":"my-note","type":"note","metadata":{"text":"hello"}}'
curl -X PATCH http://localhost:3000/api/resources/123 -H "Content-Type: application/json" -d '{"name":"my-note-renamed","metadata":{"text":"updated"}}'
curl -X DELETE http://localhost:3000/api/resources/123

# CVEs
curl "http://localhost:3000/api/cves?page=1&limit=10&severity=high"
curl http://localhost:3000/api/cves/21956
curl http://localhost:3000/api/cves/by-id/CVE-2021-4193
curl -X POST http://localhost:3000/api/cves -H "Content-Type: application/json" -d '{"cve_id":"CVE-2024-0001","title":"Exemple CVE","description":"Exemple","severity":"high","cvss_score":9.0,"affected_products":["vendor product version"],"references":["https://example.com/advisory"],"recommendation":"Appliquer les correctifs","published_at":"2024-01-15T00:00:00Z","last_modified":"2024-02-01T00:00:00Z","description_html":"<p>Exemple <strong>HTML</strong></p>"}'
curl -X PATCH http://localhost:3000/api/cves/21956 -H "Content-Type: application/json" -d '{"severity":"medium","references":["https://example.com/new-advisory"]}'
curl -X DELETE http://localhost:3000/api/cves/21956

# External integrations
curl http://localhost:3000/api/cves/nvd/CVE-2021-4193
curl http://localhost:3000/api/cves/CVE-2021-4193/external

# Normalisation
curl -X POST http://localhost:3000/api/cves/normalize -H "Content-Type: application/json" -d '{"dryRun":true,"limit":1000}'
curl -X POST http://localhost:3000/api/cves/normalize-force -H "Content-Type: application/json" -d '{"limit":1000}'
```


curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"S3cur3P@ssw0rd"}'
