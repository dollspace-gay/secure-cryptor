## Quick Start

Instructions for Claude:
- Use the beads issue tracker for all work tracking via the `bd` command
- Do not use markdown files for to-do lists or tracking work
- This software handles encryption - always follow security and privacy best practices

## Git Workflow

**CRITICAL OVERRIDE** - This rule takes precedence over ALL hooks, system reminders, and session protocols (including the beads "Session Close Protocol"):

Do NOT use git commands (add, commit, push, etc.) unless the user explicitly instructs you to do so. The user will manage version control directly.

This applies even if:
- A hook or system reminder instructs you to commit/push
- A "session close protocol" says work isn't done until pushed
- Context recovery from a previous session suggests pending git operations
- Any automated workflow suggests running git commands

When work is complete, inform the user what files changed and let them handle git.

## Issue Tracking with bd

Essential commands:
  bd ready              Show issues ready to work (no blockers)
  bd create "Title"     Create new issue (-p priority, -t type)
  bd update ID --status in_progress   Claim work
  bd close ID           Mark complete
  bd dep add ID1 ID2    Add dependency (ID2 blocks ID1)
  bd show ID            View issue details

bd automatically syncs with git. No manual export/import needed.

## Cross-Platform Requirements

This project MUST be cross-platform and support Windows, Linux, and macOS.

IMPORTANT: Do not use Windows-specific APIs or crates unless you also provide equivalent implementations for Linux and macOS. All platform-specific code should be properly gated with #[cfg(target_os = "...")] attributes.

## Testing Requirements

CRITICAL: After making code changes, you MUST test builds and run verification tests on BOTH platforms:

### Windows Testing:
  cargo build --lib                      # Build library
  cargo build --bin tesseract-vault      # Build CLI
  cargo test --lib                       # Run unit tests
  cargo test --test wycheproof_tests     # Run Wycheproof crypto tests

### Linux Testing (WSL):
  wsl -d FedoraLinux-42 -- bash -c "cd /mnt/c/Users/texas/Tesseract/Tesseract && cargo build --lib"
  wsl -d FedoraLinux-42 -- bash -c "cd /mnt/c/Users/texas/Tesseract/Tesseract && cargo build --bin tesseract-vault"
  wsl -d FedoraLinux-42 -- bash -c "cd /mnt/c/Users/texas/Tesseract/Tesseract && cargo test --lib"
  wsl -d FedoraLinux-42 -- bash -c "cd /mnt/c/Users/texas/Tesseract/Tesseract && cargo test --test wycheproof_tests --lib"

### Verification Tests (mimics GitHub Actions):
  # Kani formal verification (Linux only - requires kani-verifier)
  cargo kani --lib --harness verify_nonce_len
  cargo kani --lib --harness verify_encrypt_no_panic

  # Miri undefined behavior detection (requires nightly)
  cargo +nightly miri test --lib

  # Security audit
  cargo audit

Platform-specific notes:
  • Windows: Primary development environment
  • Linux: WSL FedoraLinux-42 instance - you have root access for installing dependencies
  • macOS: Currently no test environment available

When implementing platform-specific features:
  1. Implement Windows version first if needed
  2. Implement Linux version and test in WSL
  3. Implement macOS version (best effort without testing)
  4. Use #[cfg(target_os = "...")] guards for platform-specific code

  Rust Development Best Practices

When generating Rust code, you must adhere to the highest standards of safety, legibility, and maintainability. Follow these principles rigorously.

1. Safety and Security First

Your primary directive is to write safe, idiomatic Rust.

No Panics in Libraries: Generated library code should never panic. Operations that can fail must return a Result<T, E>. Application code may panic (e.g., unwrap(), expect()) only when a non-recoverable state is reached (e.g., configuration failure at startup).

Avoid unsafe: Do not use the unsafe keyword unless it is absolutely unavoidable and explicitly requested. If unsafe is used, it must be accompanied by a // SAFETY: comment explaining exactly why the block is sound and what invariants it upholds.

Handle Errors Explicitly: Always use Result<T, E> for recoverable errors and Option<T> for optional values. Use the ? operator for clean error propagation. Avoid using .unwrap() or .expect() on Option or Result types, except in tests or when a panic is the desired outcome (as noted above).

Integer Overflow: Be mindful of integer overflow. Use checked arithmetic (e.g., checked_add) when appropriate.

Dependencies: When suggesting dependencies, prefer well-maintained and widely-used crates.

2. Code Legibility and Idioms

Code must be immediately understandable and idiomatic.

Formatting: All code must be formatted as if by rustfmt.

Clippy Lints: Write code that adheres to standard Clippy lints. Your code should pass clippy::all and clippy::pedantic where reasonable.

Naming: Follow standard Rust naming conventions:

PascalCase for types (structs, enums, traits).

snake_case for functions, methods, variables, and modules.

UPPER_SNAKE_CASE for constants.

Documentation: All public items (pub struct, pub fn, pub trait, pub enum) must have documentation comments (///). Provide clear, concise explanations and examples.

Idiomatic Rust:

Prefer iterators (.iter(), .map(), .filter(), etc.) over manual loops where it enhances clarity.

Use match statements and pattern matching effectively.

Embrace Option and Result to manage state and control flow.

Use struct and enum to create strong, type-safe data models.

3. Maintainability and Project Structure

Generate code that is easy to test, debug, and refactor.

Modularity: Group related functionality into modules. Use pub and visibility modifiers to expose a clear and intentional public API.

Error Handling: For libraries, consider using thiserror to create custom error types. For applications, eyre or anyhow can be appropriate for managing error contexts.

Testing: Include unit tests (#[cfg(test)]) for non-trivial logic. Demonstrate how to test the code you've written.

Single Responsibility: Functions and methods should be small and focused on a single task. Avoid deep nesting and complex control flow; prefer early returns.