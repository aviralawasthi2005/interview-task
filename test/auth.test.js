const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

// Import utilities
const { hashPassword, comparePassword } = require("../src/utils/password");
const {
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  hashToken,
} = require("../src/utils/token");

// Import backward compatibility modules
const utlisPassword = require("../src/utlis/password");
const utlisToken = require("../src/utlis/token");

const app = require("../src/server");

test("Password Utility: hashing and comparison", async () => {
  const plain = "SuperSecretPassword123";
  const hashed = await hashPassword(plain);

  assert.notEqual(hashed, plain);
  assert.equal(typeof hashed, "string");

  const isMatch = await comparePassword(plain, hashed);
  assert.equal(isMatch, true);

  const isBadMatch = await comparePassword("WrongPassword", hashed);
  assert.equal(isBadMatch, false);
});

test("Backward Compatibility: src/utlis exports match src/utils", async () => {
  assert.equal(typeof utlisPassword.hashPassword, "function");
  assert.equal(typeof utlisPassword.comparePassword, "function");
  assert.equal(typeof utlisToken.createAccessToken, "function");
  assert.equal(typeof utlisToken.createRefreshToken, "function");
});

test("Token Utility: access and refresh token lifecycle", () => {
  const mockUser = {
    _id: "507f1f77bcf86cd799439011",
    email: "test@example.com",
    role: "user",
  };

  const accessToken = createAccessToken(mockUser);
  assert.equal(typeof accessToken, "string");

  const decodedAccess = verifyAccessToken(accessToken);
  assert.equal(decodedAccess.sub, mockUser._id);
  assert.equal(decodedAccess.email, mockUser.email);
  assert.equal(decodedAccess.role, "user");

  const refreshToken = createRefreshToken(mockUser);
  assert.equal(typeof refreshToken, "string");

  const decodedRefresh = verifyRefreshToken(refreshToken);
  assert.equal(decodedRefresh.sub, mockUser._id);
  assert.equal(decodedRefresh.type, "refresh");

  const hashed = hashToken(refreshToken);
  assert.equal(typeof hashed, "string");
  assert.equal(hashed.length, 64); // SHA-256 hex length
});

test("Token Utility: reject invalid tokens", () => {
  assert.throws(() => {
    verifyAccessToken("invalid.jwt.token");
  });

  assert.throws(() => {
    verifyRefreshToken("invalid.jwt.token");
  });
});

test("HTTP Server Integration Tests", async (t) => {
  let server;
  let baseUrl;

  // Start server on ephemeral port (0)
  await new Promise((resolve) => {
    server = http.createServer(app).listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://localhost:${port}`;
      resolve();
    });
  });

  t.after(() => {
    server.close();
  });

  await t.test("GET /health returns healthy status", async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);

    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.message, "Server is running");
    assert.ok(data.database);
  });

  await t.test("GET /api/health returns identical status", async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.equal(res.status, 200);

    const data = await res.json();
    assert.equal(data.success, true);
  });

  await t.test("POST /api/auth/register validates missing fields", async () => {
    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    // When DB is unavailable, requireDatabase middleware returns 503; if DB were connected, validation returns 400
    assert.ok([400, 503].includes(res.status));
    const data = await res.json();
    assert.equal(data.success, false);
  });

  await t.test("POST /api/auth/login validates missing credentials", async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    assert.ok([400, 503].includes(res.status));
    const data = await res.json();
    assert.equal(data.success, false);
  });

  await t.test("GET /api/auth/profile requires authorization header", async () => {
    const res = await fetch(`${baseUrl}/api/auth/profile`);
    assert.equal(res.status, 401);

    const data = await res.json();
    assert.equal(data.success, false);
    assert.equal(data.message, "Authorization header missing");
  });

  await t.test("GET /api/auth/profile rejects invalid bearer format", async () => {
    const res = await fetch(`${baseUrl}/api/auth/profile`, {
      headers: { Authorization: "Basic dXNlcjpwYXNz" },
    });
    assert.equal(res.status, 401);

    const data = await res.json();
    assert.equal(data.success, false);
    assert.equal(data.message, "Invalid Bearer token format");
  });

  await t.test("GET /api/auth/profile rejects invalid token", async () => {
    const res = await fetch(`${baseUrl}/api/auth/profile`, {
      headers: { Authorization: "Bearer bad.token.here" },
    });
    assert.equal(res.status, 401);

    const data = await res.json();
    assert.equal(data.success, false);
    assert.equal(data.message, "Invalid or expired token");
  });

  await t.test("GET non-existent API route returns 404 JSON", async () => {
    const res = await fetch(`${baseUrl}/api/unknown-endpoint`, {
      headers: { Accept: "application/json" },
    });
    assert.equal(res.status, 404);

    const data = await res.json();
    assert.equal(data.success, false);
    assert.equal(data.message, "Route not found");
  });
});
