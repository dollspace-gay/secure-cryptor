## Quick Start

Instructions for Claude
For all work in this repository, you must use the beads issue tracker.
Use the bd command-line tool to create, manage, and close issues.
Do not use markdown files for creating to-do lists or for tracking your work. All issues and bugs are to be tracked via bd. This software is used for encryption and decryption so you will always stringently follow best security and privacy practices in coding.

bd - Dependency-Aware Issue Tracker

Issues chained together like beads.

GETTING STARTED
  bd init   Initialize bd in your project
            Creates .beads/ directory with project-specific database        
            Auto-detects prefix from directory name (e.g., myapp-1, myapp-2)

  bd init --prefix api   Initialize with custom prefix
            Issues will be named: api-1, api-2, ...

CREATING ISSUES
  bd create "Fix login bug"
  bd create "Add auth" -p 0 -t feature
  bd create "Write tests" -d "Unit tests for auth" --assignee alice

VIEWING ISSUES
  bd list       List all issues
  bd list --status open  List by status
  bd list --priority 0  List by priority (0-4, 0=highest)
  bd show bd-1       Show issue details

MANAGING DEPENDENCIES
  bd dep add bd-1 bd-2     Add dependency (bd-2 blocks bd-1)
  bd dep tree bd-1  Visualize dependency tree
  bd dep cycles      Detect circular dependencies

DEPENDENCY TYPES
  blocks  Task B must complete before task A
  related  Soft connection, doesn't block progress
  parent-child  Epic/subtask hierarchical relationship
  discovered-from  Auto-created when AI discovers related work

READY WORK
  bd ready       Show issues ready to work on
            Ready = status is 'open' AND no blocking dependencies
            Perfect for agents to claim next work!

UPDATING ISSUES
  bd update bd-1 --status in_progress
  bd update bd-1 --priority 0
  bd update bd-1 --assignee bob

CLOSING ISSUES
  bd close bd-1
  bd close bd-2 bd-3 --reason "Fixed in PR #42"

DATABASE LOCATION
  bd automatically discovers your database:
    1. --db /path/to/db.db flag
    2. $BEADS_DB environment variable
    3. .beads/*.db in current directory or ancestors
    4. ~/.beads/default.db as fallback

AGENT INTEGRATION
  bd is designed for AI-supervised workflows:
    • Agents create issues when discovering new work
    • bd ready shows unblocked work ready to claim
    • Use --json flags for programmatic parsing
    • Dependencies prevent agents from duplicating effort
	
GIT WORKFLOW (AUTO-SYNC)
  bd automatically keeps git in sync:
    • ✓ Export to JSONL after CRUD operations (5s debounce)
    • ✓ Import from JSONL when newer than DB (after git pull)
    • ✓ Works seamlessly across machines and team members
    • No manual export/import needed!
  Disable with: --no-auto-flush or --no-auto-import

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