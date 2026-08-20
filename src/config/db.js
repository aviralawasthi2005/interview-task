const mongoose = require("mongoose");

const connectDB = async () => {
  const mongoUri = process.env.MONGODB_URI;

  if (!mongoUri) {
    console.warn("Missing required environment variable: MONGODB_URI. Database features will be unavailable until it is set.");
    return null;
  }

  try {
    await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log("MongoDB connected");
    return mongoose.connection;
  } catch (error) {
    console.warn("MongoDB connection failed:", error.message);
    return null;
  }
};

module.exports = connectDB;
