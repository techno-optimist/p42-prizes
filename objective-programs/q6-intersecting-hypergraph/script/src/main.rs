use p42_q6_objective_core::{
    sha256, verify_q6_intersecting_hypergraph_and_journal, word_u128, ObjectiveWitness,
    SCORE_ATOM_SCALE,
};
use sp1_sdk::{
    blocking::{MockProver, Prover},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use std::{env, fs, process};

const ELF: Elf = include_elf!("p42-q6-objective-program");

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("identity") if args.next().is_none() => print_identity(ELF),
        Some("identity-elf") => {
            let path = args.next().ok_or("usage: ... identity-elf PROGRAM.elf")?;
            if args.next().is_some() {
                return Err("usage: ... identity-elf PROGRAM.elf".into());
            }
            print_identity(fs::read(path).map_err(|error| error.to_string())?.into())
        }
        Some("execute-fixture") => {
            let path = args
                .next()
                .ok_or("usage: ... execute-fixture SOLUTION.json")?;
            if args.next().is_some() {
                return Err("usage: ... execute-fixture SOLUTION.json".into());
            }
            execute_fixture(ELF, fs::read(path).map_err(|error| error.to_string())?)
        }
        Some("execute-fixture-elf") => {
            let elf_path = args
                .next()
                .ok_or("usage: ... execute-fixture-elf PROGRAM.elf SOLUTION.json")?;
            let solution_path = args
                .next()
                .ok_or("usage: ... execute-fixture-elf PROGRAM.elf SOLUTION.json")?;
            if args.next().is_some() {
                return Err("usage: ... execute-fixture-elf PROGRAM.elf SOLUTION.json".into());
            }
            execute_fixture(
                fs::read(elf_path)
                    .map_err(|error| error.to_string())?
                    .into(),
                fs::read(solution_path).map_err(|error| error.to_string())?,
            )
        }
        _ => Err("usage: p42-q6-objective-script identity | execute-fixture SOLUTION.json".into()),
    }
}

fn print_identity(elf: Elf) -> Result<(), String> {
    let prover = MockProver::new();
    let elf_sha256 = sha256(&elf);
    let pk = prover.setup(elf).map_err(|error| error.to_string())?;
    println!(
        "{{\"schema\":\"p42-objective-program-identity/v1\",\"guestElfSha256\":\"0x{}\",\"programVKey\":\"{}\",\"publicValuesBytes\":32,\"sp1Version\":\"6.1.0\"}}",
        hex::encode(elf_sha256), pk.verifying_key().bytes32(),
    );
    Ok(())
}

fn execute_fixture(elf: Elf, solution: Vec<u8>) -> Result<(), String> {
    let prover = MockProver::new();
    let pk = prover
        .setup(elf.clone())
        .map_err(|error| error.to_string())?;
    let vkey: [u8; 32] = hex::decode(pk.verifying_key().bytes32().trim_start_matches("0x"))
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "bad vkey")?;
    let witness = ObjectiveWitness {
        chain_id: word_u128(84_532),
        quorum: [0x11; 20],
        manager: [0x22; 20],
        submission_manager: [0x33; 20],
        registry: [0x44; 20],
        problem_id: word_u128(1),
        objective_package_hash: [0x55; 32],
        guest_elf_sha256: sha256(&elf),
        program_vkey: vkey,
        submission_id: word_u128(7),
        solver: [0x66; 20],
        commitment: [0x77; 32],
        commit_da_hash: sha256(&solution),
        solution_cid: b"ipfs://p42-q6-fixture".to_vec(),
        claimed_score_atoms: word_u128(17 * SCORE_ATOM_SCALE),
        improvement_atoms: word_u128(SCORE_ATOM_SCALE),
        challenge_ends_at: word_u128(2_000_000_300),
        challenger: [0x88; 20],
        reason_hash: [0x99; 32],
        challenged_at: word_u128(2_000_000_100),
        dispute_ends_at: word_u128(2_000_000_200),
        pending_challenger_wins: false,
        transcript_hash: [0xaa; 32],
        transcript_uri: b"ipfs://p42-q6-transcript".to_vec(),
        verdict_hash: [0xbb; 32],
        corrected_challenger_wins: true,
        proof_beneficiary: [0xcc; 20],
        solution,
    };
    let expected = verify_q6_intersecting_hypergraph_and_journal(&witness)
        .map_err(|error| error.to_string())?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);
    let (public_values, report) = prover
        .execute(elf.clone(), stdin)
        .run()
        .map_err(|error| error.to_string())?;
    if public_values.as_slice() != expected {
        return Err("guest public values mismatch".into());
    }
    println!("{{\"schema\":\"p42-objective-execution/v1\",\"guestElfSha256\":\"0x{}\",\"programVKey\":\"{}\",\"journalDigest\":\"0x{}\",\"publicValuesBytes\":32,\"totalInstructionCount\":{}}}", hex::encode(sha256(&elf)), pk.verifying_key().bytes32(), hex::encode(expected), report.total_instruction_count());
    Ok(())
}
