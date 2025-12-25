import { Pool, QueryResult, QueryResultRow } from "pg";

const DATABASE_URL= "postgres://postgres@Localhost:5432/postgres";

const pool = new Pool({
    connectionString: DATABASE_URL,
});

pool.on('connect', () => {
    console.log("Connected to the database successfully.");
});

const query = <T extends QueryResultRow = any>(
  text: string,
  params?: any[]
): Promise<QueryResult<T>> => {
  return pool.query<T>(text, params);
};

export default query;