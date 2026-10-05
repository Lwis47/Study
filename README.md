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

### Render environment variables

The Blueprint configures `NODE_ENV=production`, generates a strong `SESSION_SECRET`, obtains `DATABASE_URL` from the Render PostgreSQL database, and sets `DATABASE_SSL=false` for Render's private network connection. It also sets `SMTP_HOST=smtp-relay.brevo.com`, `SMTP_PORT=2525`, and `SMTP_SECURE=false` (STARTTLS is used by Nodemailer).

Enter these three values in Render when prompted by the Blueprint:

| Variable | What to enter |
| --- | --- |
| `SMTP_USER` | The SMTP login shown in Brevo under SMTP/API settings. This is not necessarily your Brevo account email. |
| `SMTP_PASS` | A Brevo SMTP key. Create/copy an SMTP key; do not use a Brevo API key here. |
| `EMAIL_FROM` | A sender address verified in Brevo, for example `Cypher-School <no-reply@yourdomain.com>`. Replace the example domain with your verified sender. |
| `ADMIN_BOOTSTRAP_KEY` | A random secret of at least 32 characters. Generate one with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Use it once to create the first admin, then remove it from Render. |

`APP_BASE_URL` is optional. If set, use the exact public URL, such as `https://cypher-school.onrender.com`, with no trailing slash. When omitted, the server uses Render's assigned service URL. Render supplies `PORT` automatically; do not add it yourself. Do not set a second `DATABASE_URL` manually when using the Blueprint, because it is linked to the database service.

The web service is on Render's free plan in this Blueprint, so the SMTP port is set to Brevo's port `2525`. Use the host and port above for that plan.

Before the first successful deploy, set `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM`, and `ADMIN_BOOTSTRAP_KEY` on the web service. Registration verification and password recovery emails need the SMTP values. Then deploy. To create the first admin on the free web plan, send a `POST` request to `https://your-service.onrender.com/api/admin/bootstrap`, set the `x-admin-bootstrap-key` header to your generated secret and the `Origin` header to the same service URL, and send JSON with `fullName`, `username`, `email`, and `password` (10–128 characters). The route is one-time and becomes unavailable once an administrator exists. Remove `ADMIN_BOOTSTRAP_KEY` from Render immediately after it succeeds. If using a paid service with Shell access instead, you can run `npm run admin:create`.

After the first successful deploy:

1. Visit the service URL and sign in to the admin account you bootstrapped.
2. Use **Admin panel** to manage users and resources.

The Blueprint binds the web service to `0.0.0.0` through `PORT`, uses `/api/health` as its health check, and keeps PostgreSQL private to the service.

## Backend features

- PostgreSQL accounts and resource records, with bcrypt password hashing.
- Email verification before sign-in, resend verification, one-time 30-minute password reset links, and password change notices. Email tokens are stored as hashes and rate-limited.
- Server-side PostgreSQL sessions using HttpOnly, SameSite cookies.
- Login/register throttling, same-origin mutation checks, input limits, Helmet headers, and admin authorization on the server.
- Account profile, password, and deletion endpoints.
- Administrator user search, role/status changes, password reset email, export, and deletion. The server protects the last active administrator.
- PDF resource submissions stored in PostgreSQL until an administrator approves or rejects them.
- `/api/health` readiness check.

The free Render web tier sleeps when idle; this affects wake-up time but not database persistence. Do not use the free PostgreSQL plan for real learner accounts because it expires after 30 days.
