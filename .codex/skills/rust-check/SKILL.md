Idiomatic Rust Patterns
Use Concise Control Flow
Prefer ? operator over explicit match statements for error propagation:

// Good
let result = operation()?;

// Avoid
match operation() {
    Ok(val) => val,
    Err(e) => return Err(MyError::from(e)),
}
Use if let instead of match when handling single patterns:

// Good
if let Some(value) = option {
    do_something(value);
}

// Avoid
match option {
    Some(value) => do_something(value),
    None => {}
}
Use while let for loop patterns:

// Good
while let Some(item) = iterator.next() {
    process(item);
}

// Avoid
loop {
    match iterator.next() {
        Some(item) => process(item),
        None => break,
    }
}
Iterator Patterns
Prefer iterator chains over manual loops:

// Good
let results: Vec<_> = items
    .iter()
    .filter(|item| item.is_valid())
    .map(|item| item.process())
    .collect();

// Avoid
let mut results = Vec::new();
for item in &items {
    if item.is_valid() {
        results.push(item.process());
    }
}
Use functional combinators (filter_map, flatten, fold, etc.) instead of intermediate collections

Error Handling
Use ? operator over explicit error conversions when error types can be automatically converted via From trait or #[from] attribute:
// Good: Use ? when NoteError has #[from] std::io::Error
let file = File::open("data.txt")?;

// Avoid: Explicit map_err when automatic conversion works
let file = File::open("data.txt").map_err(NoteError::from)?;
Use map_err only when you need custom error transformation that cannot be handled by the From trait:
// Good: Custom error context that can't be expressed via From
let file = File::open("data.txt").map_err(|e| NoteError::IoWithContext(e, "failed to open config"))?;
Prefer anyhow or thiserror for application-level error handling
Use Result extensions like ok_or, and_then, or_else for complex flows
Other Idiomatic Patterns
Prefer destructuring assignments where appropriate
Use .. spread operator in struct updates
Leverage From/Into traits for conversions
Use AsRef/AsMut bounds for flexible parameter types
Import Grouping
Group imports from same crate using curly braces:

// Good: Grouped imports
use mdnotes_lib::{NoteError, Result};
use mdnotes_lib::repository::{NoteRepository, fs::FileSystemRepository};

// Avoid: Multiple separate imports
use mdnotes_lib::NoteError;
use mdnotes_lib::Result;
use mdnotes_lib::repository::NoteRepository;
use mdnotes_lib::repository::fs::FileSystemRepository;
Use qualified paths sparingly - prefer imports over fully-qualified names in function signatures:

// Good: Using imported types
pub async fn handle_create(title: String, content: Option<String>) -> Result<()> {
    // ...
}

// Avoid: Fully-qualified in signatures (verbose)
pub async fn handle_create(title: String, content: Option<String>) -> mdnotes_lib::Result<()> {
    // ...
}
Project Philosophy
Avoid Overengineering
Implement exactly what's required by task specifications and acceptance criteria
Cover specified edge cases but avoid adding extra functionality unless explicitly requested
Focus on essential features - resist the urge to add bells and whistles
Keep changes minimal and targeted - only modify what's necessary to fulfill requirements
Refactor only when essential or explicitly requested
Commands
Build
cargo build
cargo build --release
Test
cargo test
cargo test --all
Run
cargo run -- create "Test Note" --content "Hello"
cargo run -- list
cargo run -- search "test"
Check
cargo check
cargo clippy
Code Style
Rust Standards
Follow standard Rust naming conventions (snake_case for functions/variables, CamelCase for types)
Use thiserror for custom error types
Prefer ? operator over match for error propagation
Use async/await for I/O operations
Derive common traits: Debug, Clone, PartialEq where applicable
Documentation
Use /// for public API documentation
Include examples in doc comments
Document panics and errors
Testing
Write unit tests in #[cfg(test)] modules
Use tempfile for filesystem tests
Use assert_cmd for CLI integration tests
Follow test-first development (Constitution II)
Quality Assurance
Upon completion of each task that involves Rust code, AI agents MUST run the following commands to ensure code quality and consistency:

Required Checks
# Format all Rust code
cargo fmt

# Run linter and static analysis
cargo clippy
Why These Checks Matter
cargo fmt: Ensures consistent code formatting across the entire codebase, following Rust's standard style guide
cargo clippy: Catches common mistakes, idiomatic issues, and provides suggestions for better Rust code
When to Run
After completing any implementation task
Before marking a task as done
Before creating a pull request or committing changes
After any code modification in the crates/ directory
Handling Errors
If cargo fmt or cargo clippy report issues:

Fix all warnings and errors reported by clippy
Re-run formatting if needed
Verify the fixes don't break existing tests
Re-run both commands to confirm compliance