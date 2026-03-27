import { DataSource } from "typeorm";

declare const dataSource: DataSource;
declare const userId: string;

const query = `SELECT * FROM users WHERE id = ${userId}`;

export async function loadUser() {
  return dataSource.query(query);
}
