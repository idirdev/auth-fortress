import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth';
import { config } from './config';

const app = express();

// ── Global middleware ──────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: config.cors.origin,
  credentials: true,
}));
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

// ── Health check ───────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'auth-fortress',
    timestamp: new Date().toISOString(),
  });
});

// ── Auth routes ────────────────────────────────────────────────────────
app.use('/auth', authRoutes);

// ── 404 fallback ───────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Global error handler ──────────────────────────────────────────────
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[auth-fortress] Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ──────────────────────────────────────────────────────────────
app.listen(config.port, () => {
  console.log(`[auth-fortress] Running on port ${config.port} (${config.nodeEnv})`);
  console.log(`[auth-fortress] Access token expiry: ${config.jwt.accessExpiry}`);
  console.log(`[auth-fortress] Refresh token expiry: ${config.jwt.refreshExpiry}`);
});

export default app;
