# SP1 build pending

This directory has no active SP1 dependency, guest manifest, build script, ELF,
vkey, or activation identity. SP1 6.3.1 is not an acceptable activation pin.

The files under `program/` and `script/` are non-buildable design scaffolding.
They may be activated only after an actual patched upstream release or
maintained fork has received external security review and the repository pins
its exact source, version, and dependency closure. That change must also:

1. deserialize a full objective challenge witness with the solution field
   bounded to 4 MiB before JSON parsing;
2. call the core's `evaluate_and_journal`, committing exactly 32 bytes of
   `P42_OBJECTIVE_VERDICT_JOURNAL_V2` output;
3. regenerate and independently reproduce the ELF and vkey; and
4. add genuine proof replay and Solidity journal differential evidence.

SP1 frames stdin before typed deserialization. A bounded solution-field visitor
prevents oversized solution allocation inside bincode, but the host must also
cap total framed stdin. Invalid solution JSON maps to
`expected_score_atoms=None` and can produce a challenger-winning journal;
malformed witness framing or a failed envelope assertion aborts guest execution.
