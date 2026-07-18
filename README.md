# TitanBag Cloud Sharing Sync Backend (PostgreSQL)

This directory contains a lightweight, production-ready companion REST API server that facilitates user accounts, invitation-based partner connections, and offline-first journal synchronizations utilizing a **PostgreSQL** database.

---

## Technical Stack
* **Runtime:** Node.js
* **Framework:** Express.js
* **Database Client:** pg (node-postgres connection pool)
* **Auth:** Password hashing using bcryptjs, token sessions using JSON Web Tokens (JWT)

---

## Quick Start Setup

### 1. Database Provisioning
1. Set up a PostgreSQL database instance.
2. Retrieve your database connection string (e.g. `postgresql://user:password@host:port/database`).
3. Ensure you have the `piggybag` schema and the required tables set up.

### 2. Environment Configuration
Create a `.env` file in this directory (`d:\projects\titanBag\.env`) containing the connection parameters:

```env
DATABASE_URL=your_postgresql_connection_string
JWT_SECRET=any_random_cryptographic_secret_string
PORT=5000
```

*Note: If your database password contains special characters (like `+`, `:`, `#`), make sure they are percent-encoded inside the connection URL.*

### 3. Server Startup
Make sure you have [Node.js](https://nodejs.org/) installed, and run:

```bash
# Install dependencies
npm install

# Run server
npm start
```

Upon startup, the script will automatically seed base global default categories into the `piggybag.categories` table if they do not exist.

---

## API Endpoints

* **POST** `/register` – Register cloud profiles, generating deterministic EXP invitation codes.
* **POST** `/login` – Authenticate username/email, issuing JWT.
* **GET** `/profile` – Retrieve profile and connected partner states.
* **POST** `/partner/connect` – Binds user accounts using EXP invitation codes or usernames.
* **DELETE** / **POST** `/partner/disconnect` – Unlinks partner relations.
* **POST** `/sync` – Batch uploads local changes and pulls partner datasets, resolving conflicts.
