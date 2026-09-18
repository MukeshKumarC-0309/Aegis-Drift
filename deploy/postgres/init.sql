-- Extensions the application benefits from. Created once, at first cluster init.
CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- trigram indexes for ILIKE search
CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid()
