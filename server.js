/*
 * Copyright (c) 2026 Alex Nord.
 * Licensed under the PolyForm Noncommercial License 1.0.0.
 * Commercial use is prohibited without written permission.
 *
 * This project is source-available for noncommercial use only.
 */
import express from "express";
import session from "express-session";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ── VATSIM OAuth config ────────────────────────────────────────────────────
const VATSIM_AUTH_URL = "https://auth.vatsim.net";
const CLIENT_ID = process.env.VATSIM_CLIENT_ID || "YOUR_CLIENT_ID";
const CLIENT_SECRET = process.env.VATSIM_CLIENT_SECRET || "YOUR_CLIENT_SECRET";
const REDIRECT_URI = process.env.REDIRECT_URI || `http://localhost:${PORT}/callback`;

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "vatsim-heatmap-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
  })
);
app.use(express.static(path.join(__dirname, "public")));

// ── Auth routes ────────────────────────────────────────────────────────────
app.get("/auth/login", (req, res) => {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "full_name vatsim_details email",
    required_scopes: "vatsim_details",
    state: Math.random().toString(36).substring(2),
  });
  res.redirect(`${VATSIM_AUTH_URL}/oauth/authorize?${params}`);
});

app.get("/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    return res.redirect("/?error=auth_failed");
  }

  try {
    // Exchange code for token
    const tokenRes = await fetch(`${VATSIM_AUTH_URL}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        code,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error("No access token");

    // Fetch user info
    const userRes = await fetch(`${VATSIM_AUTH_URL}/api/user`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const userData = await userRes.json();

    req.session.user = {
      cid: userData.data?.cid,
      name: userData.data?.personal?.name_full,
      access_token: tokenData.access_token,
    };

    res.redirect("/");
  } catch (err) {
    console.error("Auth error:", err);
    res.redirect("/?error=token_exchange_failed");
  }
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/auth/me", (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, user: req.session.user });
  } else {
    res.json({ authenticated: false });
  }
});

// ── VATSIM Data routes ─────────────────────────────────────────────────────

// Cache the VATSIM data feed (update every 15 seconds max)
let vatsimDataCache = null;
let lastFetch = 0;

async function getVatsimData() {
  const now = Date.now();
  if (vatsimDataCache && now - lastFetch < 15000) return vatsimDataCache;
  const res