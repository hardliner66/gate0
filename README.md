# gate0

A small, auditable, terminating, deterministic micro-policy engine.

## Security Model

Gate0 is designed for high-assurance environments where policy evaluation must be deterministic and resource-bounded. See [SECURITY.md](SECURITY.md) for the full threat model, system invariants, and mechanical guarantees.

## Verification

The correctness and safety of Gate0 are mechanically verified:

- **Unit Tests**: Full coverage of core logic and edge cases.
- **Property-Based Testing**: Hundreds of adversarial scenarios generated via `proptest`.
- **Undefined Behavior Check**: Verified panic-free and UB-free using `cargo miri`.
- **Bounded Evaluation**: Worst-case inputs are tested to ensure termination.

```bash
cargo test
cargo +nightly miri test --lib
```

## Example

```rust
use gate0::{Policy, Rule, Target, Request, ReasonCode};

let policy = Policy::builder()
    .rule(Rule::allow(Target::any(), ReasonCode(1)))
    .build()?;

let decision = policy.evaluate(&Request::new("alice", "read", "doc"))?;
assert!(decision.is_allow());
```

## License

MIT
