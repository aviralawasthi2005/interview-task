const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");
const mongoose = require("mongoose");

dotenv.config();

const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const rateLimiter = require("./middleware/rateLimiter");

const app = express();
const PORT = Number(process.env.PORT) || 5000;

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(rateLimiter);

// Serve static frontend files from /client directory
const clientPath = path.join(__dirname, "../../client");
app.use(express.static(clientPath));

// Health check endpoint
const healthHandler = (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? "connected" : "disconnected";
  res.json({
    success: true,
    message: "Server is running",
    database: dbStatus,
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
};

app.get("/health", healthHandler);
app.get("/api/health", healthHandler);

// Authentication routes
app.use("/api/auth", authRoutes);

// Fallback route for frontend single page app or 404
app.use((req, res) => {
  if (req.accepts("html")) {
    return res.sendFile(path.join(clientPath, "index.html"), (err) => {
      if (err) {
        res.status(404).json({ success: false, message: "Route not found" });
      }
    });
  }
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// Centralized error handling middleware
app.use((err, req, res, next) => {
  console.error("Server error:", err.message);

  // Mongoose validation error
  if (err.name === "ValidationError") {
    const messages = Object.values(err.errors).map((val) => val.message);
    return res.status(400).json({
      success: false,
      message: messages[0] || "Validation Error",
      errors: messages,
    });
  }

  // MongoDB duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || "field";
    return res.status(409).json({
      success: false,
      message: `A user with this ${field} already exists`,
    });
  }

  // JWT errors
  if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
    return res.status(401).json({
      success: false,
      message: err.message,
    });
  }

  res.status(err.statusCode || 500).json({
    success: false,
    message: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,
  });
});

const startServer = async () => {
  const requiredVars = ["JWT_SECRET", "MONGODB_URI"];
  const missingVars = requiredVars.filter((key) => !process.env[key]);

  if (missingVars.length > 0) {
    console.warn(`Environment notice: Missing [${missingVars.join(", ")}]. Using development defaults.`);
  }

  await connectDB();
  return app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
};

if (require.main === module) {
  startServer();
}

module.exports = app;
module.exports.startServer = startServer;