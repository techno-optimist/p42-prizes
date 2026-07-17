BEGIN;

CREATE TABLE IF NOT EXISTS p42_indexer_checkpoint_high_water (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  finalized_block_number bigint CHECK (finalized_block_number >= 0),
  finalized_block_hash text CHECK (finalized_block_hash ~ '^0x[0-9a-f]{64}$'),
  checkpoint_digest text CHECK (checkpoint_digest ~ '^sha256:[0-9a-f]{64}$'),
  checkpoint_timestamp bigint CHECK (checkpoint_timestamp > 0),
  release_binding_digest text CHECK (release_binding_digest ~ '^sha256:[0-9a-f]{64}$'),
  authorization_digest text CHECK (authorization_digest ~ '^sha256:[0-9a-f]{64}$'),
  chain_id bigint CHECK (chain_id > 0),
  chain_name text CHECK (chain_name ~ '^[a-z][A-Za-z0-9]*$'),
  deployment_commit text CHECK (deployment_commit ~ '^[0-9a-f]{40}$'),
  deployment_config_hash text CHECK (deployment_config_hash ~ '^0x[0-9a-f]{64}$'),
  accepted_at timestamptz,
  updated_at timestamptz,
  CONSTRAINT p42_indexer_checkpoint_high_water_complete CHECK (
    (finalized_block_number IS NULL
      AND finalized_block_hash IS NULL
      AND checkpoint_digest IS NULL
      AND checkpoint_timestamp IS NULL
      AND release_binding_digest IS NULL
      AND authorization_digest IS NULL
      AND chain_id IS NULL
      AND chain_name IS NULL
      AND deployment_commit IS NULL
      AND deployment_config_hash IS NULL
      AND accepted_at IS NULL
      AND updated_at IS NULL)
    OR
    (finalized_block_number IS NOT NULL
      AND finalized_block_hash IS NOT NULL
      AND checkpoint_digest IS NOT NULL
      AND checkpoint_timestamp IS NOT NULL
      AND release_binding_digest IS NOT NULL
      AND authorization_digest IS NOT NULL
      AND chain_id IS NOT NULL
      AND chain_name IS NOT NULL
      AND deployment_commit IS NOT NULL
      AND deployment_config_hash IS NOT NULL
      AND accepted_at IS NOT NULL
      AND updated_at IS NOT NULL)
  )
);

DO $$
DECLARE
  expected_columns text[] := ARRAY[
    'accepted_at:timestamp with time zone:YES',
    'authorization_digest:text:YES',
    'chain_id:bigint:YES',
    'chain_name:text:YES',
    'checkpoint_digest:text:YES',
    'checkpoint_timestamp:bigint:YES',
    'deployment_commit:text:YES',
    'deployment_config_hash:text:YES',
    'finalized_block_hash:text:YES',
    'finalized_block_number:bigint:YES',
    'release_binding_digest:text:YES',
    'singleton:boolean:NO',
    'updated_at:timestamp with time zone:YES'
  ];
  actual_columns text[];
  expected_constraint_names text[] := ARRAY[
    'p42_indexer_checkpoint_high_water_authorization_digest_check',
    'p42_indexer_checkpoint_high_water_chain_id_check',
    'p42_indexer_checkpoint_high_water_chain_name_check',
    'p42_indexer_checkpoint_high_water_checkpoint_digest_check',
    'p42_indexer_checkpoint_high_water_checkpoint_timestamp_check',
    'p42_indexer_checkpoint_high_water_complete',
    'p42_indexer_checkpoint_high_water_deployment_commit_check',
    'p42_indexer_checkpoint_high_water_deployment_config_hash_check',
    'p42_indexer_checkpoint_high_water_finalized_block_hash_check',
    'p42_indexer_checkpoint_high_water_finalized_block_number_check',
    'p42_indexer_checkpoint_high_water_pkey',
    'p42_indexer_checkpoint_high_water_release_binding_digest_check',
    'p42_indexer_checkpoint_high_water_singleton_check'
  ];
  actual_constraint_names text[];
BEGIN
  SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable ORDER BY column_name)
    INTO actual_columns
  FROM information_schema.columns
  WHERE table_schema = current_schema()
    AND table_name = 'p42_indexer_checkpoint_high_water';
  SELECT array_agg(conname ORDER BY conname)
    INTO actual_constraint_names
  FROM pg_constraint
  WHERE conrelid = 'p42_indexer_checkpoint_high_water'::regclass
    AND contype IN ('c', 'p');

  IF actual_columns IS DISTINCT FROM expected_columns
    OR actual_constraint_names IS DISTINCT FROM expected_constraint_names
    OR NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'p42_indexer_checkpoint_high_water'
        AND column_name = 'singleton'
        AND column_default = 'true'
    )
    OR EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'p42_indexer_checkpoint_high_water'
        AND column_name <> 'singleton'
        AND column_default IS NOT NULL
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = 'p42_indexer_checkpoint_high_water'::regclass
        AND contype = 'p'
        AND pg_get_constraintdef(oid) = 'PRIMARY KEY (singleton)'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = 'p42_indexer_checkpoint_high_water'::regclass
        AND conname = 'p42_indexer_checkpoint_high_water_complete'
        AND contype = 'c'
    )
    OR EXISTS (
      SELECT 1
      FROM (VALUES
        ('p42_indexer_checkpoint_high_water_authorization_digest_check', 'CHECK ((authorization_digest ~ ''^sha256:[0-9a-f]{64}$''::text))'),
        ('p42_indexer_checkpoint_high_water_chain_id_check', 'CHECK ((chain_id > 0))'),
        ('p42_indexer_checkpoint_high_water_chain_name_check', 'CHECK ((chain_name ~ ''^[a-z][A-Za-z0-9]*$''::text))'),
        ('p42_indexer_checkpoint_high_water_checkpoint_digest_check', 'CHECK ((checkpoint_digest ~ ''^sha256:[0-9a-f]{64}$''::text))'),
        ('p42_indexer_checkpoint_high_water_checkpoint_timestamp_check', 'CHECK ((checkpoint_timestamp > 0))'),
        ('p42_indexer_checkpoint_high_water_deployment_commit_check', 'CHECK ((deployment_commit ~ ''^[0-9a-f]{40}$''::text))'),
        ('p42_indexer_checkpoint_high_water_deployment_config_hash_check', 'CHECK ((deployment_config_hash ~ ''^0x[0-9a-f]{64}$''::text))'),
        ('p42_indexer_checkpoint_high_water_finalized_block_hash_check', 'CHECK ((finalized_block_hash ~ ''^0x[0-9a-f]{64}$''::text))'),
        ('p42_indexer_checkpoint_high_water_finalized_block_number_check', 'CHECK ((finalized_block_number >= 0))'),
        ('p42_indexer_checkpoint_high_water_pkey', 'PRIMARY KEY (singleton)'),
        ('p42_indexer_checkpoint_high_water_release_binding_digest_check', 'CHECK ((release_binding_digest ~ ''^sha256:[0-9a-f]{64}$''::text))'),
        ('p42_indexer_checkpoint_high_water_singleton_check', 'CHECK (singleton)')
      ) AS expected(conname, definition)
      LEFT JOIN pg_constraint actual
        ON actual.conrelid = 'p42_indexer_checkpoint_high_water'::regclass
       AND actual.conname = expected.conname
      WHERE pg_get_constraintdef(actual.oid) IS DISTINCT FROM expected.definition
    )
    OR EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid = 'p42_indexer_checkpoint_high_water'::regclass
        AND contype NOT IN ('c', 'p', 'n')
    ) THEN
    RAISE EXCEPTION 'existing P42 indexer checkpoint high-water table does not match migration 2';
  END IF;
END $$;

INSERT INTO p42_indexer_checkpoint_high_water (singleton)
VALUES (true)
ON CONFLICT (singleton) DO NOTHING;

DO $$
BEGIN
  IF (SELECT count(*) FROM p42_indexer_checkpoint_high_water) <> 1
    OR NOT EXISTS (
      SELECT 1 FROM p42_indexer_checkpoint_high_water WHERE singleton = true
    ) THEN
    RAISE EXCEPTION 'P42 indexer checkpoint high-water singleton is invalid for migration 2';
  END IF;
END $$;

INSERT INTO p42_schema_migration (version, name)
VALUES (2, 'indexer_checkpoint_high_water')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name
WHERE p42_schema_migration.name = EXCLUDED.name;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM p42_schema_migration
    WHERE version = 2 AND name = 'indexer_checkpoint_high_water'
  ) THEN
    RAISE EXCEPTION 'P42 schema migration version 2 is bound to another name';
  END IF;
END $$;

COMMIT;
