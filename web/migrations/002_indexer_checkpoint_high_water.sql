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

CREATE TABLE IF NOT EXISTS p42_indexer_checkpoint_authority (
  singleton boolean NOT NULL DEFAULT true,
  database_oid oid NOT NULL,
  database_name name NOT NULL,
  schema_oid oid NOT NULL,
  schema_name name NOT NULL,
  migration_owner_oid oid NOT NULL,
  migration_owner_name name NOT NULL,
  authority_oid oid NOT NULL,
  control_oid oid NOT NULL,
  epoch_oid oid NOT NULL,
  acceptance_oid oid NOT NULL,
  transition_function_oid oid NOT NULL,
  transition_function_source text NOT NULL,
  exact_read_function_oid oid NOT NULL,
  exact_read_function_source text NOT NULL,
  CONSTRAINT p42_indexer_checkpoint_authority_pkey PRIMARY KEY (singleton),
  CONSTRAINT p42_indexer_checkpoint_authority_singleton_true CHECK (singleton),
  CONSTRAINT p42_indexer_checkpoint_authority_oids_positive CHECK (
    database_oid > 0 AND schema_oid > 0 AND migration_owner_oid > 0
    AND authority_oid > 0 AND control_oid > 0 AND epoch_oid > 0
    AND acceptance_oid > 0 AND transition_function_oid > 0 AND exact_read_function_oid > 0
  )
);

DO $$ BEGIN
  IF (SELECT count(*) FROM information_schema.columns
      WHERE table_schema=current_schema() AND table_name='p42_indexer_checkpoint_epoch'
        AND column_name IN ('release_binding_digest','authorization_digest','chain_id','chain_name',
          'deployment_commit','deployment_config_hash'))=6
  THEN
    IF EXISTS (
      SELECT 1 FROM p42_indexer_checkpoint_epoch
      GROUP BY release_binding_digest,authorization_digest,chain_id,chain_name,
        deployment_commit,deployment_config_hash
      HAVING count(*)>1
    ) THEN
      RAISE EXCEPTION 'existing checkpoint historical full identity replay';
    END IF;
  END IF;
END $$;

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

DO $migration$
DECLARE
  target_schema name := current_schema();
  owner_name name := current_user;
  function_identity text;
  exact_function_identity text;
BEGIN
  IF target_schema IS NULL OR target_schema = 'pg_catalog' OR target_schema LIKE 'pg_temp_%' THEN
    RAISE EXCEPTION 'P42 checkpoint migration requires a durable explicit schema';
  END IF;

  EXECUTE format($definition$
    CREATE OR REPLACE FUNCTION %1$I.p42_transition_indexer_checkpoint(
      p_finalized_block_number bigint,
      p_finalized_block_hash text,
      p_checkpoint_digest text,
      p_checkpoint_timestamp bigint,
      p_release_binding_digest text,
      p_authorization_digest text,
      p_chain_id bigint,
      p_chain_name text,
      p_deployment_commit text,
      p_deployment_config_hash text
    ) RETURNS TABLE (
      transition_kind text,
      epoch_id bigint,
      release_binding_digest text,
      authorization_digest text,
      chain_id bigint,
      chain_name text,
      deployment_commit text,
      deployment_config_hash text,
      epoch_accepted_at timestamptz,
      acceptance_id bigint,
      finalized_block_number bigint,
      finalized_block_hash text,
      checkpoint_digest text,
      checkpoint_timestamp bigint,
      acceptance_accepted_at timestamptz,
      current_epoch bigint,
      current_acceptance bigint,
      next_epoch bigint,
      next_acceptance bigint,
      control_updated_at timestamptz
    )
    LANGUAGE plpgsql
    SECURITY DEFINER
    VOLATILE
    SET search_path = pg_catalog
    AS $function$
    DECLARE
      authority %1$I.p42_indexer_checkpoint_authority%%ROWTYPE;
      control %1$I.p42_indexer_checkpoint_control%%ROWTYPE;
      current_identity %1$I.p42_indexer_checkpoint_epoch%%ROWTYPE;
      current_checkpoint %1$I.p42_indexer_checkpoint_acceptance%%ROWTYPE;
      max_epoch bigint;
      max_acceptance bigint;
      epoch_count bigint;
      acceptance_count bigint;
      kind text;
    BEGIN
      SELECT a.* INTO STRICT authority
        FROM %1$I.p42_indexer_checkpoint_authority AS a WHERE a.singleton = true;
      IF authority.database_oid <> (SELECT d.oid FROM pg_catalog.pg_database AS d WHERE d.datname = pg_catalog.current_database())
        OR authority.database_name::text <> pg_catalog.current_database()
        OR authority.schema_oid <> (SELECT n.oid FROM pg_catalog.pg_namespace AS n WHERE n.nspname = %2$L)
        OR authority.schema_name::text <> %2$L
        OR authority.migration_owner_oid <> (SELECT r.oid FROM pg_catalog.pg_roles AS r WHERE r.rolname = CURRENT_USER)
        OR authority.migration_owner_name::text <> CURRENT_USER
        OR authority.migration_owner_oid <> (SELECT d.datdba FROM pg_catalog.pg_database AS d WHERE d.oid=authority.database_oid)
        OR authority.migration_owner_oid <> (SELECT n.nspowner FROM pg_catalog.pg_namespace AS n WHERE n.oid=authority.schema_oid)
        OR authority.migration_owner_oid <> (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=authority.authority_oid)
        OR authority.migration_owner_oid <> (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=authority.control_oid)
        OR authority.migration_owner_oid <> (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=authority.epoch_oid)
        OR authority.migration_owner_oid <> (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=authority.acceptance_oid)
        OR authority.authority_oid <> %7$L::pg_catalog.regclass::oid
        OR authority.control_oid <> %3$L::pg_catalog.regclass::oid
        OR authority.epoch_oid <> %4$L::pg_catalog.regclass::oid
        OR authority.acceptance_oid <> %5$L::pg_catalog.regclass::oid
        OR authority.transition_function_oid <> %6$L::pg_catalog.regprocedure::oid
        OR authority.transition_function_source <> (SELECT p.prosrc FROM pg_catalog.pg_proc AS p
          WHERE p.oid = %6$L::pg_catalog.regprocedure::oid)
        OR authority.exact_read_function_oid <> %8$L::pg_catalog.regprocedure::oid
        OR authority.exact_read_function_source <> (SELECT p.prosrc FROM pg_catalog.pg_proc AS p
          WHERE p.oid = %8$L::pg_catalog.regprocedure::oid)
      THEN RAISE EXCEPTION 'checkpoint database authority identity mismatch'; END IF;

      IF p_finalized_block_number < 0 OR p_checkpoint_timestamp <= 0 OR p_chain_id <= 0
        OR p_finalized_block_hash !~ '^0x[0-9a-f]{64}$'
        OR p_checkpoint_digest !~ '^sha256:[0-9a-f]{64}$'
        OR p_release_binding_digest !~ '^sha256:[0-9a-f]{64}$'
        OR p_authorization_digest !~ '^sha256:[0-9a-f]{64}$'
        OR p_chain_name !~ '^[a-z][A-Za-z0-9]*$'
        OR p_deployment_commit !~ '^[0-9a-f]{40}$'
        OR p_deployment_config_hash !~ '^0x[0-9a-f]{64}$'
      THEN RAISE EXCEPTION 'checkpoint transition candidate is invalid'; END IF;

      SELECT c.* INTO STRICT control
        FROM %1$I.p42_indexer_checkpoint_control AS c WHERE c.singleton = true FOR UPDATE;
      SELECT max(e.epoch_id), count(*) INTO max_epoch, epoch_count FROM %1$I.p42_indexer_checkpoint_epoch AS e;
      SELECT max(a.acceptance_id), count(*) INTO max_acceptance, acceptance_count FROM %1$I.p42_indexer_checkpoint_acceptance AS a;
      max_epoch := coalesce(max_epoch, 0); max_acceptance := coalesce(max_acceptance, 0);
      IF max_epoch <> epoch_count OR max_acceptance <> acceptance_count
        OR EXISTS (SELECT 1 FROM %1$I.p42_indexer_checkpoint_epoch AS e
          WHERE NOT EXISTS (SELECT 1 FROM %1$I.p42_indexer_checkpoint_acceptance AS a WHERE a.epoch_id = e.epoch_id))
      THEN RAISE EXCEPTION 'checkpoint immutable history is not contiguous and complete'; END IF;

      IF max_epoch = 0 OR max_acceptance = 0 THEN
        IF max_epoch <> 0 OR max_acceptance <> 0 OR control.current_epoch IS NOT NULL
          OR control.current_acceptance IS NOT NULL OR control.next_epoch <> 1
          OR control.next_acceptance <> 1 OR control.updated_at IS NOT NULL
        THEN RAISE EXCEPTION 'checkpoint control does not match immutable history maxima'; END IF;
        kind := 'first';
        INSERT INTO %1$I.p42_indexer_checkpoint_epoch (
          epoch_id, release_binding_digest, authorization_digest, chain_id, chain_name,
          deployment_commit, deployment_config_hash, accepted_at
        ) VALUES (1, p_release_binding_digest, p_authorization_digest, p_chain_id, p_chain_name,
          p_deployment_commit, p_deployment_config_hash, pg_catalog.clock_timestamp());
        INSERT INTO %1$I.p42_indexer_checkpoint_acceptance (
          acceptance_id, epoch_id, finalized_block_number, finalized_block_hash,
          checkpoint_digest, checkpoint_timestamp, accepted_at
        ) VALUES (1, 1, p_finalized_block_number, p_finalized_block_hash,
          p_checkpoint_digest, p_checkpoint_timestamp, pg_catalog.clock_timestamp());
        UPDATE %1$I.p42_indexer_checkpoint_control AS c SET
          current_epoch = 1, current_acceptance = 1, next_epoch = 2, next_acceptance = 2,
          updated_at = pg_catalog.clock_timestamp() WHERE c.singleton = true;
      ELSE
        IF control.current_epoch <> max_epoch OR control.current_acceptance <> max_acceptance
          OR control.next_epoch <> max_epoch + 1 OR control.next_acceptance <> max_acceptance + 1
        THEN RAISE EXCEPTION 'checkpoint control does not match immutable history maxima'; END IF;
        SELECT e.* INTO STRICT current_identity FROM %1$I.p42_indexer_checkpoint_epoch AS e WHERE e.epoch_id = max_epoch;
        SELECT a.* INTO STRICT current_checkpoint FROM %1$I.p42_indexer_checkpoint_acceptance AS a WHERE a.acceptance_id = max_acceptance;
        IF current_checkpoint.epoch_id <> current_identity.epoch_id THEN
          RAISE EXCEPTION 'checkpoint current acceptance does not belong to current epoch';
        END IF;

        IF current_identity.release_binding_digest = p_release_binding_digest
          AND current_identity.authorization_digest = p_authorization_digest
          AND current_identity.chain_id = p_chain_id AND current_identity.chain_name = p_chain_name
          AND current_identity.deployment_commit = p_deployment_commit
          AND current_identity.deployment_config_hash = p_deployment_config_hash
        THEN
          IF p_checkpoint_timestamp < current_checkpoint.checkpoint_timestamp THEN
            RAISE EXCEPTION 'activated checkpoint timestamp regression';
          ELSIF p_finalized_block_number < current_checkpoint.finalized_block_number THEN
            RAISE EXCEPTION 'activated checkpoint finalized block regression';
          ELSIF p_finalized_block_number = current_checkpoint.finalized_block_number THEN
            IF p_finalized_block_hash <> current_checkpoint.finalized_block_hash
              OR p_checkpoint_digest <> current_checkpoint.checkpoint_digest
              OR p_checkpoint_timestamp <> current_checkpoint.checkpoint_timestamp
            THEN RAISE EXCEPTION 'activated checkpoint same-height conflict'; END IF;
            kind := 'same';
          ELSE
            kind := 'advance';
            INSERT INTO %1$I.p42_indexer_checkpoint_acceptance (
              acceptance_id, epoch_id, finalized_block_number, finalized_block_hash,
              checkpoint_digest, checkpoint_timestamp, accepted_at
            ) VALUES (max_acceptance + 1, max_epoch, p_finalized_block_number, p_finalized_block_hash,
              p_checkpoint_digest, p_checkpoint_timestamp, pg_catalog.clock_timestamp());
            UPDATE %1$I.p42_indexer_checkpoint_control AS c SET
              current_acceptance = max_acceptance + 1, next_acceptance = max_acceptance + 2,
              updated_at = pg_catalog.clock_timestamp() WHERE c.singleton = true;
          END IF;
        ELSE
          IF EXISTS (SELECT 1 FROM %1$I.p42_indexer_checkpoint_epoch AS e
            WHERE e.release_binding_digest = p_release_binding_digest
              AND e.authorization_digest = p_authorization_digest AND e.chain_id = p_chain_id
              AND e.chain_name = p_chain_name AND e.deployment_commit = p_deployment_commit
              AND e.deployment_config_hash = p_deployment_config_hash)
          THEN RAISE EXCEPTION 'activated checkpoint historical identity replay'; END IF;
          IF p_checkpoint_timestamp <= current_checkpoint.checkpoint_timestamp THEN
            RAISE EXCEPTION 'activated checkpoint epoch timestamp must strictly advance';
          END IF;
          IF current_identity.chain_id = p_chain_id AND current_identity.chain_name = p_chain_name THEN
            IF p_finalized_block_number <= current_checkpoint.finalized_block_number THEN
              RAISE EXCEPTION 'same-chain identity renewal requires a strictly higher finalized block';
            END IF;
          ELSE
            IF EXISTS (SELECT 1 FROM %1$I.p42_indexer_checkpoint_epoch AS e
              WHERE e.chain_id = p_chain_id AND e.chain_name = p_chain_name)
            THEN RAISE EXCEPTION 'historical chain identity replay'; END IF;
            IF p_release_binding_digest = current_identity.release_binding_digest
              OR p_authorization_digest = current_identity.authorization_digest
              OR p_deployment_config_hash = current_identity.deployment_config_hash
            THEN RAISE EXCEPTION 'chain transition requires new release, authorization, and deployment configuration identities'; END IF;
          END IF;
          kind := 'renew';
          INSERT INTO %1$I.p42_indexer_checkpoint_epoch (
            epoch_id, release_binding_digest, authorization_digest, chain_id, chain_name,
            deployment_commit, deployment_config_hash, accepted_at
          ) VALUES (max_epoch + 1, p_release_binding_digest, p_authorization_digest, p_chain_id,
            p_chain_name, p_deployment_commit, p_deployment_config_hash, pg_catalog.clock_timestamp());
          INSERT INTO %1$I.p42_indexer_checkpoint_acceptance (
            acceptance_id, epoch_id, finalized_block_number, finalized_block_hash,
            checkpoint_digest, checkpoint_timestamp, accepted_at
          ) VALUES (max_acceptance + 1, max_epoch + 1, p_finalized_block_number,
            p_finalized_block_hash, p_checkpoint_digest, p_checkpoint_timestamp, pg_catalog.clock_timestamp());
          UPDATE %1$I.p42_indexer_checkpoint_control AS c SET
            current_epoch = max_epoch + 1, current_acceptance = max_acceptance + 1,
            next_epoch = max_epoch + 2, next_acceptance = max_acceptance + 2,
            updated_at = pg_catalog.clock_timestamp() WHERE c.singleton = true;
        END IF;
      END IF;

      RETURN QUERY SELECT kind, e.epoch_id, e.release_binding_digest, e.authorization_digest,
        e.chain_id, e.chain_name, e.deployment_commit, e.deployment_config_hash, e.accepted_at,
        a.acceptance_id, a.finalized_block_number, a.finalized_block_hash, a.checkpoint_digest,
        a.checkpoint_timestamp, a.accepted_at, c.current_epoch, c.current_acceptance,
        c.next_epoch, c.next_acceptance, c.updated_at
      FROM %1$I.p42_indexer_checkpoint_control AS c
      JOIN %1$I.p42_indexer_checkpoint_epoch AS e ON e.epoch_id = c.current_epoch
      JOIN %1$I.p42_indexer_checkpoint_acceptance AS a ON a.acceptance_id = c.current_acceptance
      WHERE c.singleton = true;
    END
    $function$
  $definition$,
    target_schema,
    target_schema::text,
    format('%I.p42_indexer_checkpoint_control', target_schema),
    format('%I.p42_indexer_checkpoint_epoch', target_schema),
    format('%I.p42_indexer_checkpoint_acceptance', target_schema),
    format('%I.p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)', target_schema),
    format('%I.p42_indexer_checkpoint_authority', target_schema),
    format('%I.p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)', target_schema)
  );

  EXECUTE format($exact_definition$
    CREATE OR REPLACE FUNCTION %1$I.p42_read_exact_indexer_checkpoint(
      p_finalized_block_number bigint,
      p_finalized_block_hash text,
      p_checkpoint_digest text,
      p_checkpoint_timestamp bigint,
      p_release_binding_digest text,
      p_authorization_digest text,
      p_chain_id bigint,
      p_chain_name text,
      p_deployment_commit text,
      p_deployment_config_hash text
    ) RETURNS TABLE (
      transition_kind text,
      epoch_id bigint,
      release_binding_digest text,
      authorization_digest text,
      chain_id bigint,
      chain_name text,
      deployment_commit text,
      deployment_config_hash text,
      epoch_accepted_at timestamptz,
      acceptance_id bigint,
      finalized_block_number bigint,
      finalized_block_hash text,
      checkpoint_digest text,
      checkpoint_timestamp bigint,
      acceptance_accepted_at timestamptz,
      current_epoch bigint,
      current_acceptance bigint,
      next_epoch bigint,
      next_acceptance bigint,
      control_updated_at timestamptz
    )
    LANGUAGE plpgsql
    SECURITY DEFINER
    VOLATILE
    SET search_path = pg_catalog
    AS $exact_function$
    DECLARE
      authority %1$I.p42_indexer_checkpoint_authority%%ROWTYPE;
      control %1$I.p42_indexer_checkpoint_control%%ROWTYPE;
      current_identity %1$I.p42_indexer_checkpoint_epoch%%ROWTYPE;
      current_checkpoint %1$I.p42_indexer_checkpoint_acceptance%%ROWTYPE;
      max_epoch bigint;
      max_acceptance bigint;
    BEGIN
      SELECT a.* INTO STRICT authority
        FROM %1$I.p42_indexer_checkpoint_authority AS a WHERE a.singleton=true;
      IF authority.database_oid<>(SELECT d.oid FROM pg_catalog.pg_database AS d WHERE d.datname=pg_catalog.current_database())
        OR authority.database_name::text<>pg_catalog.current_database()
        OR authority.schema_oid<>(SELECT n.oid FROM pg_catalog.pg_namespace AS n WHERE n.nspname=%2$L)
        OR authority.schema_name::text<>%2$L
        OR authority.migration_owner_oid<>(SELECT r.oid FROM pg_catalog.pg_roles AS r WHERE r.rolname=CURRENT_USER)
        OR authority.migration_owner_name::text<>CURRENT_USER
        OR authority.migration_owner_oid<>(SELECT d.datdba FROM pg_catalog.pg_database AS d WHERE d.oid=authority.database_oid)
        OR authority.migration_owner_oid<>(SELECT n.nspowner FROM pg_catalog.pg_namespace AS n WHERE n.oid=authority.schema_oid)
        OR authority.migration_owner_oid<>(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=authority.authority_oid)
        OR authority.migration_owner_oid<>(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=authority.control_oid)
        OR authority.migration_owner_oid<>(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=authority.epoch_oid)
        OR authority.migration_owner_oid<>(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=authority.acceptance_oid)
        OR authority.authority_oid<>%7$L::pg_catalog.regclass::oid
        OR authority.control_oid<>%3$L::pg_catalog.regclass::oid
        OR authority.epoch_oid<>%4$L::pg_catalog.regclass::oid
        OR authority.acceptance_oid<>%5$L::pg_catalog.regclass::oid
        OR authority.transition_function_oid<>%6$L::pg_catalog.regprocedure::oid
        OR authority.transition_function_source<>(SELECT p.prosrc FROM pg_catalog.pg_proc AS p WHERE p.oid=%6$L::pg_catalog.regprocedure::oid)
        OR authority.exact_read_function_oid<>%8$L::pg_catalog.regprocedure::oid
        OR authority.exact_read_function_source<>(SELECT p.prosrc FROM pg_catalog.pg_proc AS p WHERE p.oid=%8$L::pg_catalog.regprocedure::oid)
      THEN RAISE EXCEPTION 'checkpoint database authority identity mismatch'; END IF;
      IF p_finalized_block_number<0 OR p_checkpoint_timestamp<=0 OR p_chain_id<=0
        OR p_finalized_block_hash!~'^0x[0-9a-f]{64}$'
        OR p_checkpoint_digest!~'^sha256:[0-9a-f]{64}$'
        OR p_release_binding_digest!~'^sha256:[0-9a-f]{64}$'
        OR p_authorization_digest!~'^sha256:[0-9a-f]{64}$'
        OR p_chain_name!~'^[a-z][A-Za-z0-9]*$'
        OR p_deployment_commit!~'^[0-9a-f]{40}$'
        OR p_deployment_config_hash!~'^0x[0-9a-f]{64}$'
      THEN RAISE EXCEPTION 'checkpoint exact-read candidate is invalid'; END IF;

      SELECT c.* INTO STRICT control FROM %1$I.p42_indexer_checkpoint_control AS c
        WHERE c.singleton=true FOR SHARE;
      SELECT e.epoch_id INTO max_epoch FROM %1$I.p42_indexer_checkpoint_epoch AS e
        ORDER BY e.epoch_id DESC LIMIT 1;
      SELECT a.acceptance_id INTO max_acceptance FROM %1$I.p42_indexer_checkpoint_acceptance AS a
        ORDER BY a.acceptance_id DESC LIMIT 1;
      IF max_epoch IS NULL OR max_acceptance IS NULL THEN
        IF max_epoch IS NOT NULL OR max_acceptance IS NOT NULL OR control.current_epoch IS NOT NULL
          OR control.current_acceptance IS NOT NULL OR control.next_epoch<>1 OR control.next_acceptance<>1
          OR control.updated_at IS NOT NULL
        THEN RAISE EXCEPTION 'checkpoint exact-read control/history mismatch'; END IF;
        RETURN;
      END IF;
      IF control.current_epoch<>max_epoch OR control.current_acceptance<>max_acceptance
        OR control.next_epoch<>max_epoch+1 OR control.next_acceptance<>max_acceptance+1
      THEN RAISE EXCEPTION 'checkpoint exact-read control does not match indexed maxima'; END IF;
      SELECT e.* INTO STRICT current_identity FROM %1$I.p42_indexer_checkpoint_epoch AS e WHERE e.epoch_id=max_epoch;
      SELECT a.* INTO STRICT current_checkpoint FROM %1$I.p42_indexer_checkpoint_acceptance AS a WHERE a.acceptance_id=max_acceptance;
      IF current_checkpoint.epoch_id<>current_identity.epoch_id THEN
        RAISE EXCEPTION 'checkpoint exact-read acceptance does not belong to current epoch';
      END IF;
      IF current_identity.release_binding_digest<>p_release_binding_digest
        OR current_identity.authorization_digest<>p_authorization_digest
        OR current_identity.chain_id<>p_chain_id OR current_identity.chain_name<>p_chain_name
        OR current_identity.deployment_commit<>p_deployment_commit
        OR current_identity.deployment_config_hash<>p_deployment_config_hash
        OR current_checkpoint.finalized_block_number<>p_finalized_block_number
        OR current_checkpoint.finalized_block_hash<>p_finalized_block_hash
        OR current_checkpoint.checkpoint_digest<>p_checkpoint_digest
        OR current_checkpoint.checkpoint_timestamp<>p_checkpoint_timestamp
      THEN RETURN; END IF;
      RETURN QUERY SELECT 'same'::text,e.epoch_id,e.release_binding_digest,e.authorization_digest,
        e.chain_id,e.chain_name,e.deployment_commit,e.deployment_config_hash,e.accepted_at,
        a.acceptance_id,a.finalized_block_number,a.finalized_block_hash,a.checkpoint_digest,
        a.checkpoint_timestamp,a.accepted_at,c.current_epoch,c.current_acceptance,
        c.next_epoch,c.next_acceptance,c.updated_at
      FROM %1$I.p42_indexer_checkpoint_control AS c
      JOIN %1$I.p42_indexer_checkpoint_epoch AS e ON e.epoch_id=c.current_epoch
      JOIN %1$I.p42_indexer_checkpoint_acceptance AS a ON a.acceptance_id=c.current_acceptance
      WHERE c.singleton=true;
    END
    $exact_function$
  $exact_definition$,
    target_schema,
    target_schema::text,
    format('%I.p42_indexer_checkpoint_control',target_schema),
    format('%I.p42_indexer_checkpoint_epoch',target_schema),
    format('%I.p42_indexer_checkpoint_acceptance',target_schema),
    format('%I.p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)',target_schema),
    format('%I.p42_indexer_checkpoint_authority',target_schema),
    format('%I.p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)',target_schema)
  );

  function_identity := format('%I.p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)', target_schema);
  exact_function_identity := format('%I.p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)', target_schema);
  EXECUTE format('ALTER FUNCTION %s OWNER TO %I', function_identity, owner_name);
  EXECUTE format('ALTER FUNCTION %s OWNER TO %I', exact_function_identity, owner_name);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', function_identity);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', exact_function_identity);
  EXECUTE format('REVOKE ALL ON %I.p42_indexer_checkpoint_authority FROM PUBLIC', target_schema);

  EXECUTE format($insert$
    INSERT INTO %1$I.p42_indexer_checkpoint_authority (
      singleton, database_oid, database_name, schema_oid, schema_name,
      migration_owner_oid, migration_owner_name, authority_oid, control_oid, epoch_oid,
      acceptance_oid, transition_function_oid, transition_function_source,
      exact_read_function_oid, exact_read_function_source
    ) VALUES (
      true,
      (SELECT d.oid FROM pg_catalog.pg_database AS d WHERE d.datname = pg_catalog.current_database()),
      pg_catalog.current_database(),
      (SELECT n.oid FROM pg_catalog.pg_namespace AS n WHERE n.nspname = %2$L),
      %2$L,
      (SELECT r.oid FROM pg_catalog.pg_roles AS r WHERE r.rolname = CURRENT_USER),
      CURRENT_USER,
      %7$L::pg_catalog.regclass::oid,
      %3$L::pg_catalog.regclass::oid,
      %4$L::pg_catalog.regclass::oid,
      %5$L::pg_catalog.regclass::oid,
      %6$L::pg_catalog.regprocedure::oid,
      (SELECT p.prosrc FROM pg_catalog.pg_proc AS p WHERE p.oid = %6$L::pg_catalog.regprocedure::oid),
      %8$L::pg_catalog.regprocedure::oid,
      (SELECT p.prosrc FROM pg_catalog.pg_proc AS p WHERE p.oid = %8$L::pg_catalog.regprocedure::oid)
    ) ON CONFLICT (singleton) DO NOTHING
  $insert$,
    target_schema,
    target_schema::text,
    format('%I.p42_indexer_checkpoint_control', target_schema),
    format('%I.p42_indexer_checkpoint_epoch', target_schema),
    format('%I.p42_indexer_checkpoint_acceptance', target_schema),
    function_identity,
    format('%I.p42_indexer_checkpoint_authority', target_schema),
    exact_function_identity
  );
END
$migration$;

DO $$
DECLARE
  authority_columns text[];
  authority_constraints text[];
  function_row record;
  exact_function_row record;
  authority_row p42_indexer_checkpoint_authority%ROWTYPE;
BEGIN
  SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || coalesce(column_default, '<null>') ORDER BY ordinal_position)
    INTO authority_columns FROM information_schema.columns
    WHERE table_schema=current_schema() AND table_name='p42_indexer_checkpoint_authority';
  SELECT array_agg(conname || ':' || pg_get_constraintdef(oid) ORDER BY conname) INTO authority_constraints
    FROM pg_constraint WHERE conrelid='p42_indexer_checkpoint_authority'::regclass AND contype IN ('c','p');
  IF authority_columns IS DISTINCT FROM ARRAY[
      'singleton:boolean:NO:true','database_oid:oid:NO:<null>','database_name:name:NO:<null>',
      'schema_oid:oid:NO:<null>','schema_name:name:NO:<null>','migration_owner_oid:oid:NO:<null>',
      'migration_owner_name:name:NO:<null>','authority_oid:oid:NO:<null>',
      'control_oid:oid:NO:<null>','epoch_oid:oid:NO:<null>',
      'acceptance_oid:oid:NO:<null>','transition_function_oid:oid:NO:<null>',
      'transition_function_source:text:NO:<null>','exact_read_function_oid:oid:NO:<null>',
      'exact_read_function_source:text:NO:<null>'
    ]::text[]
    OR authority_constraints IS DISTINCT FROM ARRAY[
      'p42_indexer_checkpoint_authority_oids_positive:CHECK (((database_oid > (0)::oid) AND (schema_oid > (0)::oid) AND (migration_owner_oid > (0)::oid) AND (authority_oid > (0)::oid) AND (control_oid > (0)::oid) AND (epoch_oid > (0)::oid) AND (acceptance_oid > (0)::oid) AND (transition_function_oid > (0)::oid) AND (exact_read_function_oid > (0)::oid)))',
      'p42_indexer_checkpoint_authority_pkey:PRIMARY KEY (singleton)',
      'p42_indexer_checkpoint_authority_singleton_true:CHECK (singleton)'
    ]::text[]
  THEN RAISE EXCEPTION 'existing P42 indexer checkpoint authority schema does not match migration 2'; END IF;

  SELECT * INTO STRICT authority_row FROM p42_indexer_checkpoint_authority WHERE singleton=true;
  SELECT p.prosecdef, p.provolatile, p.prokind, p.proconfig, p.proowner,
         l.lanname, p.proisstrict, p.proleakproof, p.proparallel, p.proretset,
         n.oid AS schema_oid, n.nspname AS schema_name, p.oid AS function_oid,
         pg_get_function_identity_arguments(p.oid) AS identity_arguments,
         pg_get_function_result(p.oid) AS function_result
    INTO STRICT function_row
    FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid=p.pronamespace
      JOIN pg_language AS l ON l.oid=p.prolang
    WHERE p.oid='p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)'::regprocedure;
  IF NOT function_row.prosecdef OR function_row.provolatile <> 'v' OR function_row.prokind <> 'f'
    OR function_row.lanname <> 'plpgsql' OR function_row.proisstrict OR function_row.proleakproof
    OR function_row.proparallel <> 'u' OR NOT function_row.proretset
    OR function_row.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']::text[]
    OR function_row.proowner <> authority_row.migration_owner_oid
    OR function_row.schema_oid <> authority_row.schema_oid
    OR function_row.schema_name <> authority_row.schema_name
    OR function_row.function_oid <> authority_row.transition_function_oid
    OR (SELECT p.prosrc FROM pg_proc AS p WHERE p.oid=function_row.function_oid)
      <> authority_row.transition_function_source
    OR function_row.identity_arguments <> 'p_finalized_block_number bigint, p_finalized_block_hash text, p_checkpoint_digest text, p_checkpoint_timestamp bigint, p_release_binding_digest text, p_authorization_digest text, p_chain_id bigint, p_chain_name text, p_deployment_commit text, p_deployment_config_hash text'
    OR function_row.function_result <> 'TABLE(transition_kind text, epoch_id bigint, release_binding_digest text, authorization_digest text, chain_id bigint, chain_name text, deployment_commit text, deployment_config_hash text, epoch_accepted_at timestamp with time zone, acceptance_id bigint, finalized_block_number bigint, finalized_block_hash text, checkpoint_digest text, checkpoint_timestamp bigint, acceptance_accepted_at timestamp with time zone, current_epoch bigint, current_acceptance bigint, next_epoch bigint, next_acceptance bigint, control_updated_at timestamp with time zone)'
    OR has_function_privilege('public', function_row.function_oid, 'EXECUTE')
  THEN RAISE EXCEPTION 'P42 checkpoint transition function authority does not match migration 2'; END IF;

  SELECT p.prosecdef, p.provolatile, p.prokind, p.proconfig, p.proowner,
         l.lanname, p.proisstrict, p.proleakproof, p.proparallel, p.proretset,
         n.oid AS schema_oid, n.nspname AS schema_name, p.oid AS function_oid,
         pg_get_function_identity_arguments(p.oid) AS identity_arguments,
         pg_get_function_result(p.oid) AS function_result
    INTO STRICT exact_function_row
    FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid=p.pronamespace
      JOIN pg_language AS l ON l.oid=p.prolang
    WHERE p.oid='p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)'::regprocedure;
  IF NOT exact_function_row.prosecdef OR exact_function_row.provolatile <> 'v' OR exact_function_row.prokind <> 'f'
    OR exact_function_row.lanname <> 'plpgsql' OR exact_function_row.proisstrict OR exact_function_row.proleakproof
    OR exact_function_row.proparallel <> 'u' OR NOT exact_function_row.proretset
    OR exact_function_row.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']::text[]
    OR exact_function_row.proowner <> authority_row.migration_owner_oid
    OR exact_function_row.schema_oid <> authority_row.schema_oid
    OR exact_function_row.schema_name <> authority_row.schema_name
    OR exact_function_row.function_oid <> authority_row.exact_read_function_oid
    OR (SELECT p.prosrc FROM pg_proc AS p WHERE p.oid=exact_function_row.function_oid)
      <> authority_row.exact_read_function_source
    OR exact_function_row.identity_arguments <> 'p_finalized_block_number bigint, p_finalized_block_hash text, p_checkpoint_digest text, p_checkpoint_timestamp bigint, p_release_binding_digest text, p_authorization_digest text, p_chain_id bigint, p_chain_name text, p_deployment_commit text, p_deployment_config_hash text'
    OR exact_function_row.function_result <> 'TABLE(transition_kind text, epoch_id bigint, release_binding_digest text, authorization_digest text, chain_id bigint, chain_name text, deployment_commit text, deployment_config_hash text, epoch_accepted_at timestamp with time zone, acceptance_id bigint, finalized_block_number bigint, finalized_block_hash text, checkpoint_digest text, checkpoint_timestamp bigint, acceptance_accepted_at timestamp with time zone, current_epoch bigint, current_acceptance bigint, next_epoch bigint, next_acceptance bigint, control_updated_at timestamp with time zone)'
    OR has_function_privilege('public', exact_function_row.function_oid, 'EXECUTE')
  THEN RAISE EXCEPTION 'P42 checkpoint exact-read function authority does not match migration 2'; END IF;
END $$;

INSERT INTO p42_indexer_checkpoint_control (singleton) VALUES (true)
ON CONFLICT (singleton) DO NOTHING;

DO $$ BEGIN
  IF (SELECT count(*) FROM p42_indexer_checkpoint_control) <> 1
    OR NOT EXISTS (SELECT 1 FROM p42_indexer_checkpoint_control WHERE singleton=true)
  THEN RAISE EXCEPTION 'P42 indexer checkpoint control singleton is invalid for migration 2'; END IF;
END $$;

DO $history_validation$
DECLARE
  max_epoch bigint;
  max_acceptance bigint;
  epoch_count bigint;
  acceptance_count bigint;
  control p42_indexer_checkpoint_control%ROWTYPE;
  violation_acceptance bigint;
BEGIN
  SELECT c.* INTO STRICT control FROM p42_indexer_checkpoint_control AS c WHERE c.singleton=true;
  SELECT coalesce(max(e.epoch_id),0),count(*) INTO max_epoch,epoch_count
    FROM p42_indexer_checkpoint_epoch AS e;
  SELECT coalesce(max(a.acceptance_id),0),count(*) INTO max_acceptance,acceptance_count
    FROM p42_indexer_checkpoint_acceptance AS a;

  IF max_epoch<>epoch_count OR max_acceptance<>acceptance_count
    OR (max_epoch=0)<>(max_acceptance=0)
    OR EXISTS (SELECT 1 FROM p42_indexer_checkpoint_epoch AS e
      WHERE NOT EXISTS (SELECT 1 FROM p42_indexer_checkpoint_acceptance AS a WHERE a.epoch_id=e.epoch_id))
  THEN RAISE EXCEPTION 'existing checkpoint history is not contiguous and complete'; END IF;

  IF max_epoch=0 THEN
    IF control.current_epoch IS NOT NULL OR control.current_acceptance IS NOT NULL
      OR control.next_epoch<>1 OR control.next_acceptance<>1 OR control.updated_at IS NOT NULL
    THEN RAISE EXCEPTION 'existing checkpoint control does not match empty history'; END IF;
    RETURN;
  END IF;
  IF control.current_epoch<>max_epoch OR control.current_acceptance<>max_acceptance
    OR control.next_epoch<>max_epoch+1 OR control.next_acceptance<>max_acceptance+1
    OR control.updated_at IS NULL
  THEN RAISE EXCEPTION 'existing checkpoint control does not match history maxima'; END IF;

  WITH ordered AS (
    SELECT a.acceptance_id,a.epoch_id,a.finalized_block_number,a.checkpoint_timestamp,
      e.chain_id,e.chain_name,e.release_binding_digest,e.authorization_digest,e.deployment_commit,e.deployment_config_hash,
      lag(a.acceptance_id) OVER (ORDER BY a.acceptance_id) AS previous_acceptance_id,
      lag(a.epoch_id) OVER (ORDER BY a.acceptance_id) AS previous_epoch_id,
      lag(a.finalized_block_number) OVER (ORDER BY a.acceptance_id) AS previous_block,
      lag(a.checkpoint_timestamp) OVER (ORDER BY a.acceptance_id) AS previous_timestamp,
      lag(e.chain_id) OVER (ORDER BY a.acceptance_id) AS previous_chain_id,
      lag(e.chain_name) OVER (ORDER BY a.acceptance_id) AS previous_chain_name,
      lag(e.release_binding_digest) OVER (ORDER BY a.acceptance_id) AS previous_release,
      lag(e.authorization_digest) OVER (ORDER BY a.acceptance_id) AS previous_authorization,
      lag(e.deployment_config_hash) OVER (ORDER BY a.acceptance_id) AS previous_config
    FROM p42_indexer_checkpoint_acceptance AS a
    JOIN p42_indexer_checkpoint_epoch AS e ON e.epoch_id=a.epoch_id
  )
  SELECT o.acceptance_id INTO violation_acceptance FROM ordered AS o
  WHERE (o.previous_acceptance_id IS NULL AND (o.acceptance_id<>1 OR o.epoch_id<>1))
    OR (o.previous_acceptance_id IS NOT NULL AND (
      o.acceptance_id<>o.previous_acceptance_id+1
      OR o.epoch_id<o.previous_epoch_id OR o.epoch_id>o.previous_epoch_id+1
      OR (o.epoch_id=o.previous_epoch_id AND (
        o.finalized_block_number<=o.previous_block OR o.checkpoint_timestamp<o.previous_timestamp))
      OR (o.epoch_id=o.previous_epoch_id+1 AND (
        o.checkpoint_timestamp<=o.previous_timestamp
        OR EXISTS (SELECT 1 FROM p42_indexer_checkpoint_epoch AS historical
          WHERE historical.epoch_id<o.epoch_id
            AND historical.release_binding_digest=o.release_binding_digest
            AND historical.authorization_digest=o.authorization_digest
            AND historical.chain_id=o.chain_id AND historical.chain_name=o.chain_name
            AND historical.deployment_commit=o.deployment_commit
            AND historical.deployment_config_hash=o.deployment_config_hash)
        OR ((o.chain_id=o.previous_chain_id AND o.chain_name=o.previous_chain_name)
          AND o.finalized_block_number<=o.previous_block)
        OR ((o.chain_id<>o.previous_chain_id OR o.chain_name<>o.previous_chain_name) AND (
          o.release_binding_digest=o.previous_release
          OR o.authorization_digest=o.previous_authorization
          OR o.deployment_config_hash=o.previous_config
          OR EXISTS (SELECT 1 FROM p42_indexer_checkpoint_epoch AS historical
            WHERE historical.epoch_id<o.epoch_id
              AND historical.chain_id=o.chain_id AND historical.chain_name=o.chain_name)
        ))
      ))
    ))
  ORDER BY o.acceptance_id LIMIT 1;
  IF violation_acceptance IS NOT NULL THEN
    RAISE EXCEPTION 'existing checkpoint semantic history regresses at acceptance %',violation_acceptance;
  END IF;

  IF EXISTS (SELECT 1 FROM p42_indexer_checkpoint_acceptance AS a
    JOIN p42_indexer_checkpoint_epoch AS e ON e.epoch_id=a.epoch_id
    WHERE a.acceptance_id=max_acceptance AND a.epoch_id<>max_epoch)
  THEN RAISE EXCEPTION 'existing current checkpoint does not belong to current epoch'; END IF;
END
$history_validation$;

INSERT INTO p42_schema_migration (version,name) VALUES (2,'indexer_checkpoint_epoch_high_water')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name
WHERE p42_schema_migration.name=EXCLUDED.name;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM p42_schema_migration WHERE version=2 AND name='indexer_checkpoint_epoch_high_water')
  THEN RAISE EXCEPTION 'P42 schema migration version 2 is bound to another name'; END IF;
END $$;
COMMIT;
