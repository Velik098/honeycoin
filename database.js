// database.js
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

sqlite3.verbose();

export async function openDatabase(dbPath) {
  const db = await open({
    filename: dbPath || path.join(__dirname, "uplio.db"),
    driver: sqlite3.Database
  });

  console.log("✅ SQLite база подключена:", dbPath);
  return db;
}
