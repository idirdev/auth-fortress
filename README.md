# Auth Fortress

![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue?logo=typescript)
![Express](https://img.shields.io/badge/Express-4.18-000?logo=express)
![License](https://img.shields.io/badge/License-MIT-green)
![Node](https://img.shields.io/badge/Node-%3E%3D18-339933?logo=node.js)

A production-ready authentication microservice built with Express and TypeScript. Implements JWT access tokens, rotating refresh tokens, bcrypt password hashing, role-based access control, and token blacklisting.

---

## Features

- **JWT Access Tokens** -- Short-lived (15 min) signed tokens for stateless authentication
- **Refresh Token Rotation** -- Long-lived (7 day) refresh tokens that rotate on each use, preventing replay attacks
- **Token Blacklisting** -- Revoke individual access tokens or all tokens for a user
- **Reuse Detection** -- If a revoked refresh token is reused, the entire token family is invalidated
- **bcrypt Password Hashing** -- Configurable salt rounds (default 12)
- **Role-Based Access Control** -- Middleware for restricting endpoints by user role (`user`, `admin`, `moderator`)
- **Zod Request Validation** -- All inputs validated with descriptive error messages
- **Security Headers** -- Helmet.js for HTTP security headers out of the box
- **CORS** -- Configurable cross-origin resource sharing

---

## API Endpoints

| Method | Endpoint         | Auth     | Description                              |
|--------|------------------|----------|------------------------------------------|
| POST   | `/auth/register` | Public   | Register a new user                      |
| POST   | `/auth/login`    | Public   | Login with email and password            |
| POST   | `/auth/refresh`  | Public   | Rotate refresh token and get new pair    |
| POST   | `/auth/logout`   | Bearer   | Revoke tokens and log out                |
| GET    | `/auth/me`       | Bearer   | Get the current authenticated user       |
| GET    | `/health`        | Public   | Health check                             |

### Request / Response Examples

**Register**
```bash
curl -X POST http://localhost:4000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass8", "name": "John Doe"}'
```

**Login**
```bash
curl -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass8"}'
```

**Refresh**
```bash
curl -X POST http://localhost:4000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<your-refresh-token>"}'
```

**Get Current User**
```bash
curl http://localhost:4000/auth/me \
  -H "Authorization: Bearer <your-access-token>"
```

**Logout**
```bash
curl -X POST http://localhost:4000/auth/logout \
  -H "Authorization: Bearer <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<your-refresh-token>"}'
```

---

## Getting Started

```bash
# 1. Clone
git clone https://github.com/idirdev/auth-fortress.git
cd auth-fortress

# 2. Install dependencies
npm install

# 3. Configure environment
cp .env.example .env
# Edit .env and set a strong JWT_SECRET

# 4. Development (with hot reload)
npm run dev

# 5. Production build
npm run build
npm start
```

---

## Project Structure

```
auth-fortress/
  src/
    config/          # Environment and app configuration
    controllers/     # Route handlers (register, login, refresh, logout, me)
    middleware/       # authenticate (JWT verify) + authorize (RBAC)
    models/          # User model and in-memory store
    routes/          # Express router definitions
    services/        # Token service (sign, verify, rotate, blacklist) + User service (CRUD)
    types/           # TypeScript interfaces and DTOs
    utils/           # Password hashing utilities
    server.ts        # Express app entry point
```

---

## Security Notes

- **Always change `JWT_SECRET`** in production. Use a cryptographically random string of at least 64 characters.
- The in-memory user and token stores are for development only. Replace them with PostgreSQL, Redis, or your database of choice before deploying.
- Refresh token rotation means each refresh token can only be used once. If a token is reused after rotation, all tokens for that user are automatically revoked (reuse detection).
- Access tokens are stateless by design but can be explicitly blacklisted on logout.
- Passwords are validated to be 8--128 characters at the API level and hashed with bcrypt (12 salt rounds by default).

---

## License

MIT

---

## 🇫🇷 Documentation en français

### Description
Auth Fortress est un microservice d'authentification prêt pour la production, construit avec Express et TypeScript. Il implémente les JWT (tokens d'accès courte durée et rotation des tokens de rafraîchissement), le hachage bcrypt, le contrôle d'accès basé sur les rôles (RBAC), et la détection de réutilisation de tokens compromis.

### Installation
```bash
# 1. Cloner le dépôt
git clone https://github.com/idirdev/auth-fortress.git
cd auth-fortress

# 2. Installer les dépendances
npm install

# 3. Configurer l'environnement
cp .env.example .env
# Modifier .env avec un JWT_SECRET sécurisé

# 4. Démarrer en mode développement
npm run dev
```

### Utilisation
Le service expose les endpoints `/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout` et `/auth/me`. Consultez la section **API Endpoints** et les exemples `curl` ci-dessus pour les détails de chaque requête. En production, remplacez les stores en mémoire par PostgreSQL et Redis.

