use p42_objective_core::{
    sha256, verify_distinct_subset_sums_a11_and_journal, word_u128, ObjectiveWitness,
    SCORE_ATOM_SCALE,
};
use sp1_sdk::{
    blocking::{MockProver, Prover},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use std::{env, fs, process};

const ELF: Elf = include_elf!("p42-distinct-subset-sums-a11-objective-program");

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("identity") => {
            if args.next().is_some() {
                return Err("usage: ... identity".into());
            }
            print_identity(ELF)
        }
        Some("identity-elf") => {
            let path = args
                .next()
                .ok_or_else(|| "usage: ... identity-elf PROGRAM.elf".to_string())?;
            if args.next().is_some() {
                return Err("usage: ... identity-elf PROGRAM.elf".into());
            }
            let elf: Elf = fs::read(path).map_err(|error| error.to_string())?.into();
            print_identity(elf)
        }
        Some("execute-fixture-elf") => {
            let elf_path = args.next().ok_or_else(|| {
                "usage: ... execute-fixture-elf PROGRAM.elf SOLUTION.json".to_string()
            })?;
            let solution_path = args.next().ok_or_else(|| {
                "usage: ... execute-fixture-elf PROGRAM.elf SOLUTION.json".to_string()
            })?;
            if args.next().is_some() {
                return Err(
                    "usage: ... execute-fixture-elf PROGRAM.elf SOLUTION.json".into(),
                );
            }
            let elf: Elf = fs::read(elf_path)
                .map_err(|error| error.to_string())?
                .into();
            let solution = fs::read(solution_path).map_err(|error| error.to_string())?;
            let prover = MockProver::new();
            let pk = prover
                .setup(elf.clone())
                .map_err(|error| error.to_string())?;
            let witness = conformance_witness(
                solution,
                sha256(&elf),
                parse_word(&pk.verifying_key().bytes32())?,
            );
            execute_witness(&prover, &pk, elf, witness)
        }
        Some("execute") => {
            let path = args
                .next()
                .ok_or_else(|| "usage: ... execute WITNESS.json".to_string())?;
            if args.next().is_some() {
                return Err("usage: ... execute WITNESS.json".into());
            }
            let raw = fs::read(path).map_err(|error| error.to_string())?;
            let witness: ObjectiveWitness =
                serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
            let prover = MockProver::new();
            let pk = prover.setup(ELF).map_err(|error| error.to_string())?;
            execute_witness(&prover, &pk, ELF, witness)
        }
        Some("execute-fixture") => {
            let path = args
                .next()
                .ok_or_else(|| "usage: ... execute-fixture SOLUTION.json".to_string())?;
            if args.next().is_some() {
                return Err("usage: ... execute-fixture SOLUTION.json".into());
            }
            let solution = fs::read(path).map_err(|error| error.to_string())?;
            let prover = MockProver::new();
            let pk = prover.setup(ELF).map_err(|error| error.to_string())?;
            let witness = conformance_witness(
                solution,
                sha256(&ELF),
                parse_word(&pk.verifying_key().bytes32())?,
            );
            execute_witness(&prover, &pk, ELF, witness)
        }
        _ => Err(
            "usage: p42-distinct-subset-sums-a11-objective-script identity | execute WITNESS.json | execute-fixture SOLUTION.json"
                .into(),
        ),
    }
}

fn execute_witness(
    prover: &MockProver,
    pk: &impl ProvingKey,
    elf: Elf,
    witness: ObjectiveWitness,
) -> Result<(), String> {
    let expected =
        verify_distinct_subset_sums_a11_and_journal(&witness).map_err(|error| error.to_string())?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);
    let elf_sha256 = sha256(&elf);
    let (public_values, report) = prover
        .execute(elf, stdin)
        .run()
        .map_err(|error| error.to_string())?;
    if public_values.as_slice() != expected {
        return Err(format!(
            "guest public values mismatch: expected 0x{}, got 0x{}",
            hex::encode(expected),
            hex::encode(public_values.as_slice())
        ));
    }
    if public_values.as_slice().len() != 32 {
        return Err("guest emitted a non-32-byte public journal".into());
    }
    println!(
        "{{\"schema\":\"p42-objective-execution/v1\",\"guestElfSha256\":\"0x{}\",\"programVKey\":\"{}\",\"journalDigest\":\"0x{}\",\"publicValuesBytes\":32,\"totalInstructionCount\":{}}}",
        hex::encode(elf_sha256),
        pk.verifying_key().bytes32(),
        hex::encode(expected),
        report.total_instruction_count(),
    );
    Ok(())
}

fn print_identity(elf: Elf) -> Result<(), String> {
    let prover = MockProver::new();
    let elf_sha256 = sha256(&elf);
    let pk = prover.setup(elf).map_err(|error| error.to_string())?;
    println!(
        "{{\"schema\":\"p42-objective-program-identity/v1\",\"guestElfSha256\":\"0x{}\",\"programVKey\":\"{}\",\"publicValuesBytes\":32,\"sp1Version\":\"6.1.0\"}}",
        hex::encode(elf_sha256),
        pk.verifying_key().bytes32(),
    );
    Ok(())
}

fn conformance_witness(
    solution: Vec<u8>,
    guest_elf_sha256: [u8; 32],
    program_vkey: [u8; 32],
) -> ObjectiveWitness {
    ObjectiveWitness {
        chain_id: word_u128(84_532),
        quorum: [0x11; 20],
        manager: [0x22; 20],
        submission_manager: [0x33; 20],
        registry: [0x44; 20],
        problem_id: word_u128(7),
        objective_package_hash: [0x55; 32],
        guest_elf_sha256,
        program_vkey,
        submission_id: word_u128(7),
        solver: [0x66; 20],
        commitment: [0x77; 32],
        commit_da_hash: sha256(&solution),
        solution_cid: b"ipfs://p42-a11-objective-fixture".to_vec(),
        claimed_score_atoms: word_u128(594 * SCORE_ATOM_SCALE),
        improvement_atoms: word_u128(0),
        challenge_ends_at: word_u128(2_000_000_300),
        challenger: [0x88; 20],
        reason_hash: [0x99; 32],
        challenged_at: word_u128(2_000_000_100),
        dispute_ends_at: word_u128(2_000_000_200),
        pending_challenger_wins: false,
        transcript_hash: [0xaa; 32],
        transcript_uri: b"ipfs://p42-a11-transcript-fixture".to_vec(),
        verdict_hash: [0xbb; 32],
        corrected_challenger_wins: true,
        proof_beneficiary: [0xcc; 20],
        solution,
    }
}

fn parse_word(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "program vkey must contain exactly 32 bytes".to_string())
}
