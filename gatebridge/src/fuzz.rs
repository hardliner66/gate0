//! Differential fuzzer: finds semantic divergences between evaluators.

use crate::ast::{EvalRequest, PolicyFile};
use crate::{shadow_evaluate, ShadowResult};
use serde::Serialize;
use arbitrary::{Arbitrary, Unstructured};
use std::fs;
use std::path::Path;

/// Run differential fuzzing for a specified number of iterations.
pub fn run_fuzz(iterations: u32, seed: Option<u64>) {
    use rand::{RngCore, SeedableRng};
    let mut rng = if let Some(s) = seed {
        rand::rngs::StdRng::seed_from_u64(s)
    } else {
        rand::rngs::StdRng::from_entropy()
    };

    println!("Starting differential fuzzer ({} iterations)...", iterations);
    
    let mut data = [0u8; 16384]; // 16KB of randomness for each generation
    let mut mismatches = 0;

    for i in 1..=iterations {
        rng.fill_bytes(&mut data);
        let mut u = Unstructured::new(&data);

        // 1. Generate random policy
        let policy_file = match PolicyFile::arbitrary(&mut u) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // 2. Generate random request
        let request = match EvalRequest::arbitrary(&mut u) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // 3. Run shadow evaluation
        match shadow_evaluate(&policy_file, &request) {
            Ok(result) => {
                if !result.decisions_match {
                    mismatches += 1;
                    println!("\n[!] Mismatch detected at iteration {}!", i);
                    save_mismatch(i, &policy_file, &request, &result);
                }
            }
            Err(e) => {
                // Evaluation error (e.g. translation failed for this random policy)
                // We log it but continue fuzzing
                eprintln!("\n[!] Error at iteration {}: {}", i, e);
            }
        }

        if i % 1000 == 0 {
            println!("Processed {} iterations... ({} mismatches)", i, mismatches);
        }
    }

    println!("\nFuzzing complete.");
    println!("Total mismatches found: {}", mismatches);
}

fn save_mismatch(
    iteration: u32,
    policy: &PolicyFile,
    request: &EvalRequest,
    result: &ShadowResult,
) {
    let dir = Path::new("fuzz_failures");
    if !dir.exists() {
        let _ = fs::create_dir(dir);
    }

    let policy_path = dir.join(format!("fail_{}_policy.yaml", iteration));
    let request_path = dir.join(format!("fail_{}_request.json", iteration));
    let result_path = dir.join(format!("fail_{}_result.json", iteration));

    // Save policy as YAML
    if let Ok(yaml) = serde_yaml::to_string(policy) {
        let _ = fs::write(policy_path, yaml);
    }

    // Save request as JSON
    if let Ok(json) = serde_json::to_string_pretty(request) {
        let _ = fs::write(request_path, json);
    }

    // Save result as JSON
    if let Ok(json) = serde_json::to_string_pretty(result) {
        let _ = fs::write(result_path, json);
    }

    println!("  Failure artifacts saved to fuzz_failures/");
}
