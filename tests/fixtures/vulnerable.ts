import jwt from "jsonwebtoken";
import { createHash } from "crypto";

const userId = input.id;
const password = "s3cr3t-password";
const apiKey = "sk_test_1234567890abcdef";
const resetToken = Math.random().toString(36).slice(2);
const signed = jwt.sign({ userId }, "supersecret12345");
const query = `SELECT * FROM users WHERE id = ${userId}`;
const weak = createHash("md5").update(password).digest("hex");

console.log("password", password);
eval(userInput);

export function login() {
  return { signed, query, resetToken, weak, apiKey };
}
