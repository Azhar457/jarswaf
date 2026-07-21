# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "asyncpg",
# ]
# ///

import asyncio
import asyncpg
import time
import json
import uuid

# Configuration
DB_URL = "postgres://postgres:postgres@127.0.0.1:5432/postgres"
TOTAL_RECORDS = 500_000
CONCURRENCY = 50
RECORDS_PER_WORKER = TOTAL_RECORDS // CONCURRENCY
BATCH_SIZE = 1000

async def setup_db():
    conn = await asyncpg.connect(DB_URL)
    print("Creating UNLOGGED table waf_logs...")
    await conn.execute("""
        DROP TABLE IF EXISTS waf_logs;
        CREATE UNLOGGED TABLE waf_logs (
            id UUID PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            source_ip INET NOT NULL,
            host TEXT NOT NULL,
            path TEXT NOT NULL,
            payload JSONB NOT NULL
        );
        -- Create a BRIN index on timestamp for fast time-series lookup
        CREATE INDEX waf_logs_ts_brin ON waf_logs USING BRIN (timestamp);
        -- Create a GIN index on payload for fast full-text/JSON searching
        -- CREATE INDEX waf_logs_payload_gin ON waf_logs USING GIN (payload jsonb_path_ops);
    """)
    await conn.close()
    print("Database setup complete.")

async def worker(worker_id, pool):
    # Prepare dummy data
    dummy_payload = json.dumps({
        "method": "GET",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "headers": {"x-forwarded-for": "1.2.3.4"},
        "threat_score": 85,
        "matched_rules": ["SQL_INJECTION"]
    })
    
    async with pool.acquire() as conn:
        for _ in range(RECORDS_PER_WORKER // BATCH_SIZE):
            batch = []
            for _ in range(BATCH_SIZE):
                batch.append((
                    str(uuid.uuid4()),
                    "192.168.1.100",
                    "example.com",
                    "/api/v1/login",
                    dummy_payload
                ))
            
            await conn.executemany("""
                INSERT INTO waf_logs (id, source_ip, host, path, payload)
                VALUES ($1, $2, $3, $4, $5::jsonb)
            """, batch)

async def main():
    await setup_db()
    
    print(f"Starting load test: {TOTAL_RECORDS} inserts with concurrency {CONCURRENCY}")
    pool = await asyncpg.create_pool(DB_URL, min_size=CONCURRENCY, max_size=CONCURRENCY)
    
    start_time = time.time()
    
    tasks = [worker(i, pool) for i in range(CONCURRENCY)]
    await asyncio.gather(*tasks)
    
    end_time = time.time()
    duration = end_time - start_time
    inserts_per_sec = TOTAL_RECORDS / duration
    
    print(f"\\n--- LOAD TEST RESULTS ---")
    print(f"Total Time: {duration:.2f} seconds")
    print(f"Total Records: {TOTAL_RECORDS:,}")
    print(f"Throughput: {inserts_per_sec:,.2f} inserts/sec")
    
    await pool.close()

if __name__ == "__main__":
    asyncio.run(main())
