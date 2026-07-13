BEGIN;

CREATE TABLE IF NOT EXISTS p42_portal_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  schema_version integer NOT NULL CHECK (schema_version = 1),
  revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
  state jsonb NOT NULL,
  import_sha256 text NOT NULL CHECK (import_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  imported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS p42_rate_limit_bucket (
  policy_id text NOT NULL,
  subject text NOT NULL,
  count integer NOT NULL CHECK (count > 0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (policy_id, subject)
);

CREATE INDEX IF NOT EXISTS p42_rate_limit_bucket_expiry_idx
  ON p42_rate_limit_bucket (expires_at);

CREATE TABLE IF NOT EXISTS p42_schema_migration (
  version integer PRIMARY KEY CHECK (version > 0),
  name text NOT NULL UNIQUE,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DO $$
DECLARE
  portal_column_count integer;
  portal_total_columns integer;
  portal_constraints text[];
  rate_column_count integer;
  rate_total_columns integer;
  rate_constraints text[];
  rate_expiry_index_valid boolean;
BEGIN
  SELECT count(*) INTO portal_total_columns
  FROM information_schema.columns
  WHERE table_schema = current_schema() AND table_name = 'p42_portal_state';
  SELECT count(*) INTO portal_column_count
  FROM information_schema.columns
  WHERE table_schema = current_schema() AND table_name = 'p42_portal_state'
    AND is_nullable = 'NO'
    AND (column_name, data_type) IN (
      ('singleton', 'boolean'),
      ('schema_version', 'integer'),
      ('revision', 'bigint'),
      ('state', 'jsonb'),
      ('import_sha256', 'text'),
      ('imported_at', 'timestamp with time zone'),
      ('updated_at', 'timestamp with time zone')
    );
  SELECT count(*) INTO rate_column_count
  FROM information_schema.columns
  WHERE table_schema = current_schema() AND table_name = 'p42_rate_limit_bucket'
    AND is_nullable = 'NO'
    AND (column_name, data_type) IN (
      ('policy_id', 'text'),
      ('subject', 'text'),
      ('count', 'integer'),
      ('expires_at', 'timestamp with time zone')
    );
  SELECT count(*) INTO rate_total_columns
  FROM information_schema.columns
  WHERE table_schema = current_schema() AND table_name = 'p42_rate_limit_bucket';
  SELECT array_agg(pg_get_constraintdef(oid) ORDER BY pg_get_constraintdef(oid)) INTO portal_constraints
  FROM pg_constraint
  WHERE conrelid = 'p42_portal_state'::regclass
    AND contype IN ('c', 'p');
  SELECT array_agg(pg_get_constraintdef(oid) ORDER BY pg_get_constraintdef(oid)) INTO rate_constraints
  FROM pg_constraint
  WHERE conrelid = 'p42_rate_limit_bucket'::regclass
    AND contype IN ('c', 'p');
  SELECT EXISTS (
    SELECT 1
    FROM pg_class index_class
    JOIN pg_index index_meta ON index_meta.indexrelid = index_class.oid
    JOIN pg_am access_method ON access_method.oid = index_class.relam
    WHERE index_class.oid = to_regclass('p42_rate_limit_bucket_expiry_idx')
      AND index_meta.indrelid = 'p42_rate_limit_bucket'::regclass
      AND access_method.amname = 'btree'
      AND index_meta.indisvalid
      AND index_meta.indisready
      AND index_meta.indpred IS NULL
      AND index_meta.indexprs IS NULL
      AND index_meta.indnkeyatts = 1
      AND index_meta.indnatts = 1
      AND (
        SELECT array_agg(attribute.attname ORDER BY key_column.ordinality)
        FROM unnest(index_meta.indkey::smallint[]) WITH ORDINALITY AS key_column(attnum, ordinality)
        JOIN pg_attribute attribute
          ON attribute.attrelid = index_meta.indrelid
         AND attribute.attnum = key_column.attnum
      ) = ARRAY['expires_at']::name[]
  ) INTO rate_expiry_index_valid;
  IF portal_column_count <> 7 OR portal_total_columns <> 7
    OR portal_constraints IS DISTINCT FROM ARRAY[
      'CHECK ((import_sha256 ~ ''^sha256:[0-9a-f]{64}$''::text))',
      'CHECK ((revision >= 0))',
      'CHECK ((schema_version = 1))',
      'CHECK (singleton)',
      'PRIMARY KEY (singleton)'
    ]::text[]
    OR rate_column_count <> 4 OR rate_total_columns <> 4
    OR rate_constraints IS DISTINCT FROM ARRAY[
      'CHECK ((count > 0))',
      'PRIMARY KEY (policy_id, subject)'
    ]::text[]
    OR EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid IN ('p42_portal_state'::regclass, 'p42_rate_limit_bucket'::regclass)
        AND contype NOT IN ('c', 'p', 'n')
    )
    OR NOT rate_expiry_index_valid
    OR NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'p42_portal_state'
      AND column_name = 'singleton' AND column_default = 'true'
  ) OR NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'p42_portal_state'
      AND column_name = 'revision' AND column_default = '0'
  ) OR EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'p42_portal_state'
      AND column_name IN ('schema_version', 'state', 'import_sha256') AND column_default IS NOT NULL
  ) OR NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'p42_portal_state'
      AND column_name IN ('imported_at', 'updated_at') AND column_default = 'clock_timestamp()'
    GROUP BY table_name HAVING count(*) = 2
  ) OR EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'p42_rate_limit_bucket'
      AND column_default IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'existing P42 portal tables do not match migration 1';
  END IF;
END $$;

INSERT INTO p42_schema_migration (version, name)
VALUES (1, 'portal_store')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name
WHERE p42_schema_migration.name = EXCLUDED.name;

COMMIT;
