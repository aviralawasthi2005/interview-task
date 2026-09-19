const bcrypt = require("bcryptjs");

/**
 * Hash a plain text password using bcrypt with 10 salt rounds.
 * @param {string} password 
 * @returns {Promise<string>}
 */
const hashPassword = async (password) => {
  return bcrypt.hash(password, 10);
};

/**
 * Compare a plain text password with a stored hash.
 * @param {string} password 
 * @param {string} hashedPassword 
 * @returns {Promise<boolean>}
 */
const comparePassword = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};

module.exports = { hashPassword, comparePassword };
