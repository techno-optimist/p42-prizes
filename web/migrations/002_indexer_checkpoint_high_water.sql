BEGIN;

CREATE TABLE IF NOT EXISTS p42_indexer_checkpoint_epoch (
  epoch_id bigint NOT NULL,
  release_binding_digest text NOT NULL,
  authorization_digest text NOT NULL,
  chain_id bigint NOT NULL,
  chain_name text NOT NULL,
  deployment_commit text NOT NULL,
  deployment_config_hash text NOT NULL,
  accepted_at timestamptz NOT NULL,
  CONSTRAINT p42_indexer_checkpoint_epoch_pkey PRIMARY KEY (epoch_id),
  CONSTRAINT p42_indexer_checkpoint_epoch_epoch_positive CHECK (epoch_id > 0),
  CONSTRAINT p42_indexer_checkpoint_epoch_release_digest_format CHECK (release_binding_digest ~ '^sha256:[0-9a-f]{64}$'),
  CONSTRAINT p42_indexer_checkpoint_epoch_authorization_digest_format CHECK (authorization_digest ~ '^sha256:[0-9a-f]{64}$'),
  CONSTRAINT p42_indexer_checkpoint_epoch_chain_positive CHECK (chain_id > 0),
  CONSTRAINT p42_indexer_checkpoint_epoch_chain_name_format CHECK (chain_name ~ '^[a-z][A-Za-z0-9]*$'),
  CONSTRAINT p42_indexer_checkpoint_epoch_commit_format CHECK (deployment_commit ~ '^[0-9a-f]{40}$'),
  CONSTRAINT p42_indexer_checkpoint_epoch_config_hash_format CHECK (deployment_config_hash ~ '^0x[0-9a-f]{64}$'),
  CONSTRAINT p42_indexer_checkpoint_epoch_identity_key UNIQUE (
    release_binding_digest, authorization_digest, chain_id, chain_name,
    deployment_commit, deployment_config_hash
  )
);

CREATE TABLE IF NOT EXISTS p42_indexer_checkpoint_acceptance (
  acceptance_id bigint NOT NULL,
  epoch_id bigint NOT NULL,
  finalized_block_number bigint NOT NULL,
  finalized_block_hash text NOT NULL,
  checkpoint_digest text NOT NULL,
  checkpoint_timestamp bigint NOT NULL,
  accepted_at timestamptz NOT NULL,
  CONSTRAINT p42_indexer_checkpoint_acceptance_pkey PRIMARY KEY (acceptance_id),
  CONSTRAINT p42_indexer_checkpoint_acceptance_id_positive CHECK (acceptance_id > 0),
  CONSTRAINT p42_indexer_checkpoint_acceptance_epoch_fkey FOREIGN KEY (epoch_id) REFERENCES p42_indexer_checkpoint_epoch(epoch_id),
  CONSTRAINT p42_indexer_checkpoint_acceptance_block_nonnegative CHECK (finalized_block_number >= 0),
  CONSTRAINT p42_indexer_checkpoint_acceptance_block_hash_format CHECK (finalized_block_hash ~ '^0x[0-9a-f]{64}$'),
  CONSTRAINT p42_indexer_checkpoint_acceptance_digest_format CHECK (checkpoint_digest ~ '^sha256:[0-9a-f]{64}$'),
  CONSTRAINT p42_indexer_checkpoint_acceptance_timestamp_positive CHECK (checkpoint_timestamp > 0),
  CONSTRAINT p42_indexer_checkpoint_acceptance_checkpoint_key UNIQUE (checkpoint_digest),
  CONSTRAINT p42_indexer_checkpoint_acceptance_exact_key UNIQUE (
    epoch_id, finalized_block_number, finalized_block_hash, checkpoint_digest, checkpoint_timestamp
  )
);

CREATE TABLE IF NOT EXISTS p42_indexer_checkpoint_control (
  singleton boolean NOT NULL DEFAULT true,
  current_epoch bigint,
  current_acceptance bigint,
  next_epoch bigint NOT NULL DEFAULT 1,
  next_acceptance bigint NOT NULL DEFAULT 1,
  updated_at timestamptz,
  CONSTRAINT p42_indexer_checkpoint_control_pkey PRIMARY KEY (singleton),
  CONSTRAINT p42_indexer_checkpoint_control_singleton_true CHECK (singleton),
  CONSTRAINT p42_indexer_checkpoint_control_state_complete CHECK (
    (current_epoch IS NULL AND current_acceptance IS NULL
      AND next_epoch = 1 AND next_acceptance = 1 AND updated_at IS NULL)
    OR
    (current_epoch IS NOT NULL AND current_acceptance IS NOT NULL
      AND current_epoch > 0 AND current_acceptance > 0
      AND next_epoch = current_epoch + 1
      AND next_acceptance = current_acceptance + 1 AND updated_at IS NOT NULL)
  ),
  CONSTRAINT p42_indexer_checkpoint_control_current_epoch_fkey
    FOREIGN KEY (current_epoch) REFERENCES p42_indexer_checkpoint_epoch(epoch_id),
  CONSTRAINT p42_indexer_checkpoint_control_current_acceptance_fkey
    FOREIGN KEY (current_acceptance) REFERENCES p42_indexer_checkpoint_acceptance(acceptance_id)
);

DO $$
DECLARE
  epoch_columns text[]; acceptance_columns text[]; control_columns text[];
  epoch_constraints text[]; acceptance_constraints text[]; control_constraints text[];
BEGIN
  SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || coalesce(column_default, '<null>') ORDER BY ordinal_position)
    INTO epoch_columns FROM information_schema.columns
    WHERE table_schema=current_schema() AND table_name='p42_indexer_checkpoint_epoch';
  SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || coalesce(column_default, '<null>') ORDER BY ordinal_position)
    INTO acceptance_columns FROM information_schema.columns
    WHERE table_schema=current_schema() AND table_name='p42_indexer_checkpoint_acceptance';
  SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || coalesce(column_default, '<null>') ORDER BY ordinal_position)
    INTO control_columns FROM information_schema.columns
    WHERE table_schema=current_schema() AND table_name='p42_indexer_checkpoint_control';
  SELECT array_agg(conname || ':' || pg_get_constraintdef(oid) ORDER BY conname) INTO epoch_constraints
    FROM pg_constraint WHERE conrelid='p42_indexer_checkpoint_epoch'::regclass AND contype IN ('c','p','u');
  SELECT array_agg(conname || ':' || pg_get_constraintdef(oid) ORDER BY conname) INTO acceptance_constraints
    FROM pg_constraint WHERE conrelid='p42_indexer_checkpoint_acceptance'::regclass AND contype IN ('c','f','p','u');
  SELECT array_agg(conname || ':' || pg_get_constraintdef(oid) ORDER BY conname) INTO control_constraints
    FROM pg_constraint WHERE conrelid='p42_indexer_checkpoint_control'::regclass AND contype IN ('c','f','p');

  IF epoch_columns IS DISTINCT FROM ARRAY[
      'epoch_id:bigint:NO:<null>','release_binding_digest:text:NO:<null>',
      'authorization_digest:text:NO:<null>','chain_id:bigint:NO:<null>','chain_name:text:NO:<null>',
      'deployment_commit:text:NO:<null>','deployment_config_hash:text:NO:<null>',
      'accepted_at:timestamp with time zone:NO:<null>'
    ]::text[]
    OR acceptance_columns IS DISTINCT FROM ARRAY[
      'acceptance_id:bigint:NO:<null>','epoch_id:bigint:NO:<null>',
      'finalized_block_number:bigint:NO:<null>','finalized_block_hash:text:NO:<null>',
      'checkpoint_digest:text:NO:<null>','checkpoint_timestamp:bigint:NO:<null>',
      'accepted_at:timestamp with time zone:NO:<null>'
    ]::text[]
    OR control_columns IS DISTINCT FROM ARRAY[
      'singleton:boolean:NO:true','current_epoch:bigint:YES:<null>',
      'current_acceptance:bigint:YES:<null>','next_epoch:bigint:NO:1',
      'next_acceptance:bigint:NO:1','updated_at:timestamp with time zone:YES:<null>'
    ]::text[]
    OR epoch_constraints IS DISTINCT FROM ARRAY[
      'p42_indexer_checkpoint_epoch_authorization_digest_format:CHECK ((authorization_digest ~ ''^sha256:[0-9a-f]{64}$''::text))',
      'p42_indexer_checkpoint_epoch_chain_name_format:CHECK ((chain_name ~ ''^[a-z][A-Za-z0-9]*$''::text))',
      'p42_indexer_checkpoint_epoch_chain_positive:CHECK ((chain_id > 0))',
      'p42_indexer_checkpoint_epoch_commit_format:CHECK ((deployment_commit ~ ''^[0-9a-f]{40}$''::text))',
      'p42_indexer_checkpoint_epoch_config_hash_format:CHECK ((deployment_config_hash ~ ''^0x[0-9a-f]{64}$''::text))',
      'p42_indexer_checkpoint_epoch_epoch_positive:CHECK ((epoch_id > 0))',
      'p42_indexer_checkpoint_epoch_identity_key:UNIQUE (release_binding_digest, authorization_digest, chain_id, chain_name, deployment_commit, deployment_config_hash)',
      'p42_indexer_checkpoint_epoch_pkey:PRIMARY KEY (epoch_id)',
      'p42_indexer_checkpoint_epoch_release_digest_format:CHECK ((release_binding_digest ~ ''^sha256:[0-9a-f]{64}$''::text))'
    ]::text[]
    OR acceptance_constraints IS DISTINCT FROM ARRAY[
      'p42_indexer_checkpoint_acceptance_block_hash_format:CHECK ((finalized_block_hash ~ ''^0x[0-9a-f]{64}$''::text))',
      'p42_indexer_checkpoint_acceptance_block_nonnegative:CHECK ((finalized_block_number >= 0))',
      'p42_indexer_checkpoint_acceptance_checkpoint_key:UNIQUE (checkpoint_digest)',
      'p42_indexer_checkpoint_acceptance_digest_format:CHECK ((checkpoint_digest ~ ''^sha256:[0-9a-f]{64}$''::text))',
      'p42_indexer_checkpoint_acceptance_epoch_fkey:FOREIGN KEY (epoch_id) REFERENCES p42_indexer_checkpoint_epoch(epoch_id)',
      'p42_indexer_checkpoint_acceptance_exact_key:UNIQUE (epoch_id, finalized_block_number, finalized_block_hash, checkpoint_digest, checkpoint_timestamp)',
      'p42_indexer_checkpoint_acceptance_id_positive:CHECK ((acceptance_id > 0))',
      'p42_indexer_checkpoint_acceptance_pkey:PRIMARY KEY (acceptance_id)',
      'p42_indexer_checkpoint_acceptance_timestamp_positive:CHECK ((checkpoint_timestamp > 0))'
    ]::text[]
    OR control_constraints IS DISTINCT FROM ARRAY[
      'p42_indexer_checkpoint_control_current_acceptance_fkey:FOREIGN KEY (current_acceptance) REFERENCES p42_indexer_checkpoint_acceptance(acceptance_id)',
      'p42_indexer_checkpoint_control_current_epoch_fkey:FOREIGN KEY (current_epoch) REFERENCES p42_indexer_checkpoint_epoch(epoch_id)',
      'p42_indexer_checkpoint_control_pkey:PRIMARY KEY (singleton)',
      'p42_indexer_checkpoint_control_singleton_true:CHECK (singleton)',
      'p42_indexer_checkpoint_control_state_complete:CHECK ((((current_epoch IS NULL) AND (current_acceptance IS NULL) AND (next_epoch = 1) AND (next_acceptance = 1) AND (updated_at IS NULL)) OR ((current_epoch IS NOT NULL) AND (current_acceptance IS NOT NULL) AND (current_epoch > 0) AND (current_acceptance > 0) AND (next_epoch = (current_epoch + 1)) AND (next_acceptance = (current_acceptance + 1)) AND (updated_at IS NOT NULL))))'
    ]::text[]
    OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid IN (
      'p42_indexer_checkpoint_epoch'::regclass,'p42_indexer_checkpoint_acceptance'::regclass,
      'p42_indexer_checkpoint_control'::regclass) AND contype NOT IN ('c','f','n','p','u'))
  THEN RAISE EXCEPTION 'existing P42 indexer checkpoint epoch schema does not match migration 2'; END IF;
END $$;

INSERT INTO p42_indexer_checkpoint_control (singleton) VALUES (true)
ON CONFLICT (singleton) DO NOTHING;

DO $$ BEGIN
  IF (SELECT count(*) FROM p42_indexer_checkpoint_control) <> 1
    OR NOT EXISTS (SELECT 1 FROM p42_indexer_checkpoint_control WHERE singleton=true)
  THEN RAISE EXCEPTION 'P42 indexer checkpoint control singleton is invalid for migration 2'; END IF;
END $$;

INSERT INTO p42_schema_migration (version,name) VALUES (2,'indexer_checkpoint_epoch_high_water')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name
WHERE p42_schema_migration.name=EXCLUDED.name;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM p42_schema_migration WHERE version=2 AND name='indexer_checkpoint_epoch_high_water')
  THEN RAISE EXCEPTION 'P42 schema migration version 2 is bound to another name'; END IF;
END $$;
COMMIT;
