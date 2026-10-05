# Cypher-School

Static learning pages and a same-origin Node.js/Express API, backed by Render PostgreSQL.

## Run locally

Use Node.js 22 or 24 and PostgreSQL 14+.

1. Create a PostgreSQL database named `cypher_school`.
2. Copy `.env.example` to `.env` and set `DATABASE_URL` plus a random `SESSION_SECRET` of at least 32 characters.
3. Run `npm install` and `npm start`.
4. Open `http://localhost:10000`.
5. Create the first administrator with `npm run admin:create` and follow the prompts.

The server creates/updates its tables on startup. Never commit `.env` or share a database connection string.

## Deploy to Render

The included `render.yaml` defines a Node web service and a PostgreSQL database. Connect the repository to Render and create a Blueprint from this file. Render generates `SESSION_SECRET` and injects the database connection string. The database is configured on a persistent paid plan; the free Render PostgreSQL plan expires after 30 days, so it is unsuitable for long-lived user data. The web service uses the free plan and can spin down when idle.

After the first successful deploy:

1. Open the `cypher-school` service in Render and use its Shell.
2. Run `npm run admin:create` and follow the prompts. Do not add a public admin signup route.
3. Visit the service URL, sign in, then use **Admin panel** to manage users and resources.

The Blueprint binds the web service to `0.0.0.0` through `PORT`, uses `/api/health` as its health check, and keeps PostgreSQL private to the service.

## Backend features

- PostgreSQL accounts and resource records, with bcrypt password hashing.
- Server-side PostgreSQL sessions using HttpOnly, SameSite cookies.
- Login/register throttling, same-origin mutation checks, input limits, Helmet headers, and admin authorization on the server.
- Account profile, password, and deletion endpoints.
- Administrator user search, role/status changes, password reset, export, and deletion. The server protects the last active administrator.
- PDF resource submissions stored in PostgreSQL until an administrator approves or rejects them.
- `/api/health` readiness check.

The free Render web tier sleeps when idle; this affects wake-up time but not database persistence. Do not use the free PostgreSQL plan for real learner accounts because it expires after 30 days.
