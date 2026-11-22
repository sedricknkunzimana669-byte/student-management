const { promisify } = require("util");
const { randomBytes, scrypt: scryptCallback } = require("crypto");

const scrypt = promisify(scryptCallback);

async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const passwordHash = await scrypt(password, salt, 64);
  return `scrypt$${salt}$${passwordHash.toString("hex")}`;
}

module.exports = { hashPassword };
