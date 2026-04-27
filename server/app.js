const fs = require("fs");
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const { DEFAULT_DB_FILE, openDatabase } = require("../db");
const { escape } = require("querystring");

function sendPublicFile(response, fileName) {
  response.sendFile(path.join(__dirname, "..", "public", fileName));
}

function createSessionId() {
  return `SESSION-${Math.random().toString(36).slice(2, 10)}-${Date.now()}`;
}

async function createApp() {
  if (!fs.existsSync(DEFAULT_DB_FILE)) {
    throw new Error(
      `Database file not found at ${DEFAULT_DB_FILE}. Run "npm run init-db" first.`
    );
  }

  const db = openDatabase(DEFAULT_DB_FILE);
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use("/css", express.static(path.join(__dirname, "..", "public", "css")));
  app.use("/js", express.static(path.join(__dirname, "..", "public", "js")));

  app.use(async (request, response, next) => {
    const sessionId = request.cookies.sid;
    //Added a content security policy to prevent CRSF and XSS attacks. 
    // This policy only allows scripts from the same origin, which prevents malicious scripts from being loaded.
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'"
    );
    if (!sessionId) {
      request.currentUser = null;
      next();
      return;
    }

    const row = await db.get(
      `
        SELECT
          sessions.id AS session_id,
          users.id AS id,
          users.username AS username,
          users.role AS role,
          users.display_name AS display_name
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.id = ?
      `,
      [sessionId]
    );

    request.currentUser = row
      ? {
          sessionId: row.session_id,
          id: row.id,
          username: row.username,
          role: row.role,
          displayName: row.display_name
        }
      : null;

    next();
  });

  function requireAuth(request, response, next) {
    if (!request.currentUser) {
      response.status(401).json({ error: "Authentication required." });
      return;
    }

    next();
  }

  app.get("/", (_request, response) => sendPublicFile(response, "index.html"));
  app.get("/login", (_request, response) => sendPublicFile(response, "login.html"));
  app.get("/notes", (_request, response) => sendPublicFile(response, "notes.html"));
  app.get("/settings", (_request, response) => sendPublicFile(response, "settings.html"));
  //Fixed by requiring that the user is admin before sending the admin.html file. Previously,
  //the page would not check for this, and one could simply add /admin in order to reach the page.
  //The only check was on the client.
  app.get("/admin", (_request, response) => {
    if(!_request.currentUser || _request.currentUser.role !== "admin") {
      response.status(403).send("Forbidden")
      return;
    }
    sendPublicFile(response, "admin.html");
    
  });

  app.get("/api/me", (request, response) => {
    response.json({ user: request.currentUser });
  });
  //This was vulnerable to SQL injection, however, parameterized queries were added to prevent this. Otherwise, using
  //admin' 1 OR 1--, one could become admin without needing the password.
  app.post("/api/login", async (request, response) => {
    const username = String(request.body.username || "");
    const password = String(request.body.password || "");

    const query = (`
      SELECT id, username, role, display_name
      FROM users
      WHERE username = ? AND password = ?`);
    const user = await db.get(query, [username, password]);

    if (!user) {
      response.status(401).json({ error: "Invalid username or password." });
      return;
    }

    const sessionId = request.cookies.sid || createSessionId();

    await db.run("DELETE FROM sessions WHERE id = ?", [sessionId]);
    await db.run(
      "INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)",
      [sessionId, user.id, new Date().toISOString()]
    );
    //Added secure cookie handling to prevent malicious use of the cookie.
    response.cookie("sid", sessionId, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      path: "/"
    });

    response.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        displayName: user.display_name
      }
    });
  });

  app.post("/api/logout", async (request, response) => {
    if (request.cookies.sid) {
      await db.run("DELETE FROM sessions WHERE id = ?", [request.cookies.sid]);
    }

    response.clearCookie("sid");
    response.json({ ok: true });
  });

  //Parameterized queres were used in order to prevent SQL injection.
  //While it was hard to do this because of the nature of the query, it
  //was still possible to do it in such a way that the server would crash.
  app.get("/api/notes", requireAuth, async (request, response) => {
    const ownerId = request.query.ownerId || request.currentUser.id;
    const search = request.query.search || "";

    const notes = await db.all(`
      SELECT
        notes.id,
        notes.owner_id AS ownerId,
        users.username AS ownerUsername,
        notes.title,
        notes.body,
        notes.pinned,
        notes.created_at AS createdAt
      FROM notes
      JOIN users ON users.id = notes.owner_id
      WHERE notes.owner_id = ?
        AND (notes.title LIKE ? OR notes.body LIKE ?)
      ORDER BY notes.pinned DESC, notes.id DESC
    `, [ownerId, `%${search}%`, `%${search}%`]);

    response.json({ notes });
  });
  //Escaped characters which could lead to injection so that injection attacks could not be made. Previously,
  //one could have conducted an XSS attack which could steal a session cookie.
  app.post("/api/notes", requireAuth, async (request, response) => {
    const escapeHtml = s => s.
    replace(/&/g, "&amp;").
    replace(/</g, "&lt;").
    replace(/>/g, "&gt;").
    replace(/"/g, "&quot;").
    replace(/'/g, "&#39;");
    const ownerId = Number(request.body.ownerId || request.currentUser.id);
    const title = String(escapeHtml(request.body.title || ""));
    const body = String(escapeHtml(request.body.body || ""));
    const pinned = request.body.pinned ? 1 : 0;
    const result = await db.run(
      "INSERT INTO notes (owner_id, title, body, pinned, created_at) VALUES (?, ?, ?, ?, ?)",
      [ownerId, title, body, pinned, new Date().toISOString()]
    );

    response.status(201).json({
      ok: true,
      noteId: result.lastID
    });
  });

  app.get("/api/settings", requireAuth, async (request, response) => {
    const userId = Number(request.query.userId || request.currentUser.id);

    const settings = await db.get(
      `
        SELECT
          users.id AS userId,
          users.username,
          users.role,
          users.display_name AS displayName,
          settings.status_message AS statusMessage,
          settings.theme,
          settings.email_opt_in AS emailOptIn
        FROM settings
        JOIN users ON users.id = settings.user_id
        WHERE settings.user_id = ?
      `,
      [userId]
    );

    response.json({ settings });
  });
  //Added escaping to prevent injection attacks. Also added authorization
  //to make sure that the current user only edits their own settings.
  app.post("/api/settings", requireAuth, async (request, response) => {
    const escapeHtml = s => s.
    replace(/&/g, "&amp;").
    replace(/</g, "&lt;").
    replace(/>/g, "&gt;").
    replace(/"/g, "&quot;").
    replace(/'/g, "&#39;");
    if(request.body.userId != request.currentUser.id || !request.currentUser) {
      response.status(403).send("Forbidden");
      return;
    }
    const userId = Number(escapeHtml(request.body.userId || request.currentUser.id));
    const displayName = String(escapeHtml(request.body.displayName || ""));
    const statusMessage = String(escapeHtml(request.body.statusMessage || ""));
    const theme = String(escapeHtml(request.body.theme || "classic"));
    const emailOptIn = request.body.emailOptIn ? 1 : 0;

    await db.run("UPDATE users SET display_name = ? WHERE id = ?", [displayName, userId]);
    await db.run(
      "UPDATE settings SET status_message = ?, theme = ?, email_opt_in = ? WHERE user_id = ?",
      [statusMessage, theme, emailOptIn, userId]
    );

    response.json({ ok: true });
  });

  app.get("/api/settings/toggle-email", requireAuth, async (request, response) => {
    const enabled = request.query.enabled === "1" ? 1 : 0;

    await db.run("UPDATE settings SET email_opt_in = ? WHERE user_id = ?", [
      enabled,
      request.currentUser.id
    ]);

    response.json({
      ok: true,
      userId: request.currentUser.id,
      emailOptIn: enabled
    });
  });
  //Fixed authentication to require that the user is admin before returning the data.
  //This data could have been accessed without being admin.
  app.get("/api/admin/users", requireAuth, async (_request, response) => {
    if(!_request.currentUser || _request.currentUser.role !== "admin") {
      response.status(403).send("Forbidden");
      return;
    }
    const users = await db.all(`
      SELECT
        users.id,
        users.username,
        users.role,
        users.display_name AS displayName,
        COUNT(notes.id) AS noteCount
      FROM users
      LEFT JOIN notes ON notes.owner_id = users.id
      GROUP BY users.id, users.username, users.role, users.display_name
      ORDER BY users.id
    `);

    response.json({ users });
  });

  return app;
}

module.exports = {
  createApp
};
