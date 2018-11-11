# auth-fortress

> **[EN]** All-in-one authentication middleware for Node.js — JWT, API keys, rate limiting, RBAC and session management in a single composable class.
> **[FR]** Middleware d'authentification tout-en-un pour Node.js — JWT, clés API, limitation de débit, RBAC et gestion de sessions dans une seule classe composable.

---

## Features / Fonctionnalités

**[EN]**
- JWT token generation, verification and auto-expiry (HS256/RS256)
- API key validation with key store lookup
- Built-in rate limiter: per-IP sliding window, configurable limits
- Role-Based Access Control (RBAC) — attach roles to users, guard routes
- Session manager with configurable TTL and store backends
- Single `middleware()` call handles auth + rate-limit + RBAC in one pass
- Returns structured JSON errors (401 / 403 / 429) with machine-readable codes
- Zero production dependencies beyond your existing runtime

**[FR]**
- Génération, vérification et expiration automatique des tokens JWT (HS256/RS256)
- Validation des clés API avec consultation du magasin de clés
- Limiteur de débit intégré : fenêtre glissante par IP, limites configurables
- Contrôle d'accès basé sur les rôles (RBAC) — attachez des rôles aux utilisateurs, protégez les routes
- Gestionnaire de sessions avec TTL configurable et backends de stockage
- Un seul appel `middleware()` gère auth + rate-limit + RBAC en une passe
- Renvoie des erreurs JSON structurées (401 / 403 / 429) avec codes lisibles par machine
- Aucune dépendance de production au-delà de votre runtime existant

---

## Installation

```bash
npm install @idirdev/auth-fortress
```

---

## API (Programmatic) / API (Programmation)

```js
const { AuthFortress, JwtAuth, ApiKeyAuth, RateLimiter, RBAC, SessionManager } = require('@idirdev/auth-fortress');

// Full setup
const auth = new AuthFortress({
  jwt: { secret: process.env.JWT_SECRET, expiresIn: '15m' },
  apiKeys: { keys: ['key-abc123', 'key-xyz789'] },
  rateLimit: { max: 100, windowMs: 60000 },  // 100 req/min per IP
  roles: {
    admin:  ['read', 'write', 'delete'],
    editor: ['read', 'write'],
    viewer: ['read'],
  },
  sessions: { ttl: 3600, store: 'memory' },
});

// Attach as Express/Node middleware
app.use(auth.middleware({ required: true }));

// Protect a route — only admins and editors
app.delete('/articles/:id', auth.middleware({ roles: ['admin', 'editor'] }), handler);

// JWT only — generate a token
const jwt = new JwtAuth({ secret: 'mysecret', expiresIn: '1h' });
const token = jwt.sign({ userId: 42, role: 'editor' });
const payload = jwt.verify(token); // { userId: 42, role: 'editor', iat, exp }

// API key only
const apiKey = new ApiKeyAuth({ keys: ['k1', 'k2'] });
const user = apiKey.validate('k1'); // returns associated user object or null

// Standalone rate limiter
const limiter = new RateLimiter({ max: 60, windowMs: 60000 });
if (!limiter.check('192.168.1.1')) {
  // too many requests
}

// RBAC check
const rbac = new RBAC({ admin: ['read','write'], viewer: ['read'] });
rbac.hasAnyRole('admin', ['admin', 'editor']); // true
```

### Error responses / Réponses d'erreur

```json
// 401 — no token / invalid token
{ "error": "Authentication required" }
{ "error": "Token expired", "code": "TOKEN_EXPIRED" }

// 403 — insufficient role
{ "error": "Insufficient permissions" }

// 429 — rate limit exceeded
{ "error": "Too many requests" }
```

---

## License

MIT — idirdev
