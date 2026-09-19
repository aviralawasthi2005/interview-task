const express = require("express");
const mongoose = require("mongoose");
const User = require("../models/User");
const { hashPassword, comparePassword } = require("../utils/password");
const {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
  hashToken,
} = require("../utils/token");
const { authenticate } = require("../middleware/auth");

const router = express.Router();

const requireDatabase = (req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      success: false,
      message: "Database unavailable",
    });
  }
  return next();
};

const sanitizeUser = (user) => ({
  id: user._id ? user._id.toString() : user.id,
  username: user.username,
  email: user.email,
  role: user.role,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

// POST /api/auth/register
router.post("/register", requireDatabase, async (req, res, next) => {
  try {
    const { username, email, password } = req.body || {};

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Username, email, and password are required",
      });
    }

    if (typeof username !== "string" || username.trim().length < 3) {
      return res.status(400).json({
        success: false,
        message: "Username must be at least 3 characters long",
      });
    }

    if (username.trim().length > 50) {
      return res.status(400).json({
        success: false,
        message: "Username cannot exceed 50 characters",
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const emailRegex = /^\S+@\S+\.\S+$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address",
      });
    }

    if (typeof password !== "string" || password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters long",
      });
    }

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "User already exists",
      });
    }

    const hashedPassword = await hashPassword(password);
    const user = new User({
      username: username.trim(),
      email: normalizedEmail,
      password: hashedPassword,
    });

    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    user.refreshTokenHash = hashToken(refreshToken);
    await user.save();

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      token: accessToken,
      refreshToken,
      user: sanitizeUser(user),
    });
  } catch (error) {
    return next(error);
  }
});

// POST /api/auth/login
router.post("/login", requireDatabase, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail }).select("+password +refreshTokenHash");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    user.refreshTokenHash = hashToken(refreshToken);
    await user.save();

    return res.json({
      success: true,
      message: "Login successful",
      token: accessToken,
      refreshToken,
      user: sanitizeUser(user),
    });
  } catch (error) {
    return next(error);
  }
});

// POST /api/auth/refresh
router.post("/refresh", requireDatabase, async (req, res, next) => {
  try {
    const { refreshToken } = req.body || {};

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: "Refresh token is required",
      });
    }

    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired refresh token",
      });
    }

    const user = await User.findById(decoded.sub).select("+refreshTokenHash");
    if (!user || !user.refreshTokenHash) {
      return res.status(401).json({
        success: false,
        message: "Session expired or invalid user",
      });
    }

    const incomingHash = hashToken(refreshToken);
    if (incomingHash !== user.refreshTokenHash) {
      return res.status(401).json({
        success: false,
        message: "Invalid refresh token",
      });
    }

    // Issue new access token and rotate refresh token
    const newAccessToken = createAccessToken(user);
    const newRefreshToken = createRefreshToken(user);

    user.refreshTokenHash = hashToken(newRefreshToken);
    await user.save();

    return res.json({
      success: true,
      message: "Token refreshed successfully",
      token: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    return next(error);
  }
});

// POST /api/auth/logout
router.post("/logout", requireDatabase, async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    let userId = null;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.split(" ")[1];
      try {
        const { verifyAccessToken } = require("../utils/token");
        const decoded = verifyAccessToken(token);
        userId = decoded.sub;
      } catch (_) {
        // Fallback to refresh token if access token is already expired
      }
    }

    const { refreshToken } = req.body || {};
    if (!userId && refreshToken) {
      try {
        const decoded = verifyRefreshToken(refreshToken);
        userId = decoded.sub;
      } catch (_) {}
    }

    if (userId) {
      await User.findByIdAndUpdate(userId, { refreshTokenHash: null });
    }

    return res.json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    return next(error);
  }
});

// GET /api/auth/profile
router.get("/profile", authenticate, requireDatabase, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.sub);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.json({
      success: true,
      user: sanitizeUser(user),
    });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
