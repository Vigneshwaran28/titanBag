# TitanBag Cloud Sharing Sync Backend (Neon PostgreSQL)

This directory contains a lightweight, production-ready companion REST API server that facilitates user accounts, invitation-based partner connections, and offline-first journal synchronizations utilizing **Neon PostgreSQL**.

---

## Technical Stack
* **Runtime:** Node.js
* **Framework:** Express.js
* **Database Client:** pg (node-postgres connection pool)
* **Auth:** Password hashing using bcryptjs, token sessions using JSON Web Tokens (JWT)

---

## Quick Start Setup

### 1. Database Provisioning
1. Sign up for a free serverless PostgreSQL database at [Neon.tech](https://neon.tech/).
2. Create a project and retrieve your database connection string (e.g. `postgresql://alex:password@ep-cool-flower-1234.us-east-2.aws.neon.tech/neondb?sslmode=require`).

### 2. Environment Configuration
Create a `.env` file in this directory (`d:\projects\Expenso\backend\.env`) containing the connection parameters:

```env
DATABASE_URL=your_neon_postgresql_connection_string
JWT_SECRET=any_random_cryptographic_secret_string
PORT=5000
```

### 3. Server Startup
Make sure you have [Node.js](https://nodejs.org/) installed, and run:

```bash
# Navigate to the backend directory
cd backend

# Install dependencies
npm install

# Run server
npm start
```

Upon startup, the script will automatically inspect the Neon PostgreSQL database and initialize the required tables (`users`, `partners`, `journals`) if they do not exist.

---

## API Endpoints

* **POST** `/register` – Register cloud profiles, generating base codes.
* **POST** `/login` – Authenticate username/email, issuing JWT.
* **GET** `/profile` – Retrieve profile and connected partner states.
* **POST** `/partner/connect` – Binds user accounts using EXP invitation codes.
* **DELETE** `/partner/disconnect` – Unlinks partner relations.
* **POST** `/sync` – Batch uploads local changes and pulls partner datasets, resolving conflicts.
