const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const getJwtSecret = () => {
  return process.env.JWT_SECRET || "development_jwt_secret_fallback_key_2026";
};

const getRefreshSecret = () => {
  return process.env.JWT_REFRESH_SECRET || getJwtSecret();
};

/**
 * Generate a 15-minute JWT access token.
 * @param {Object} user 
 * @returns {string}
 */
const createAccessToken = (user) => {
  const userId = user._id ? user._id.toString() : user.id;
  return jwt.sign(
    {
      sub: userId,
      email: user.email,
      role: user.role || "user",
    },
    getJwtSecret(),
    { expiresIn: process.env.JWT_EXPIRES_IN || "15m" }
  );
};

/**
 * Generate a 7-day JWT refresh token.
 * @param {Object} user 
 * @returns {string}
 */
const createRefreshToken = (user) => {
  const userId = user._id ? user._id.toString() : user.id;
  return jwt.sign(
    {
      sub: userId,
      type: "refresh",
    },
    getRefreshSecret(),
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d" }
  );
};

/**
 * Verify an access token.
 * @param {string} token 
 * @returns {Object} decoded token payload
 */
const verifyAccessToken = (token) => {
  return jwt.verify(token, getJwtSecret());
};

/**
 * Verify a refresh token.
 * @param {string} token 
 * @returns {Object} decoded token payload
 */
const verifyRefreshToken = (token) => {
  const decoded = jwt.verify(token, getRefreshSecret());
  if (decoded.type !== "refresh") {
    throw new Error("Invalid token type for refresh token");
  }
  return decoded;
};

/**
 * Hash a token using SHA-256 for secure database storage.
 * @param {string} token 
 * @returns {string} hex hash
 */
const hashToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

module.exports = {
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  hashToken,
  getJwtSecret,
  getRefreshSecret,
};
