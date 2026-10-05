const readline = require("node:readline");
const bcrypt = require("bcryptjs");
const { pool, initDatabase } = require("../db");

const ask = (prompt) => new Promise((resolve) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question(prompt, (answer) => { rl.close(); resolve(answer.trim()); });
});

async function askPassword() {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") return ask("Admin password (typed input is hidden only in an interactive terminal): ");
  process.stdout.write("Admin password (10+ characters): ");
  readline.emitKeypressEvents(process.stdin);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  let value = "";
  return new Promise((resolve, reject) => {
    const finish = (error) => {
      process.stdin.off("keypress", onKey);
      process.stdin.setRawMode(false);
      process.stdout.write("\n");
      error ? reject(error) : resolve(value);
    };
    const onKey = (character, key = {}) => {
      if (key.ctrl && key.name === "c") return finish(new Error("Cancelled."));
      if (key.name === "return") return finish();
      if (key.name === "backspace") { value = value.slice(0, -1); return; }
      if (character && !key.ctrl && !key.meta) value += character;
    };
    process.stdin.on("keypress", onKey);
  });
}

async function main() {
  await initDatabase();
  const fullName = await ask("Admin full name: ");
  const username = await ask("Admin username (letters/numbers/._-): ");
  const email = (await ask("Admin email: ")).toLowerCase();
  const password = await askPassword();
  if (fullName.length < 2 || !/^[A-Za-z0-9_.-]{3,30}$/.test(username) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || password.length > 128) {
    throw new Error("Invalid admin details. Name must be 2+ characters, username 3–30 valid characters, and password 10–128 characters.");
  }
  const hash = await bcrypt.hash(password, 12);
  const result = await pool.query(
    "INSERT INTO users (full_name,username,email,password_hash,role,status,email_verified_at) VALUES ($1,$2,$3,$4,'admin','active',NOW()) RETURNING id",
    [fullName, username, email, hash],
  );
  console.log(`Administrator created (${result.rows[0].id}). Sign in with ${username}.`);
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; }).finally(() => pool.end());
