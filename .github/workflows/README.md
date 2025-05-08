# CI/CD Workflows

This directory contains GitHub Actions workflows for continuous integration and deployment of the PAMP Auth Service.

## Workflows

### 1. Format Check (`format.yml`)
- Checks that all Rust code follows standard formatting rules using `rustfmt`
- Runs on all PRs and pushes to master
- Will fail if any code doesn't match the standard Rust format
- Posts formatting errors as PR comments

### 2. Tests (`test.yml`)
- Runs all tests with a PostgreSQL database
- Configured with test environment variables
- Runs on all PRs and pushes to master

### 3. Docker Build (`build.yml`)
- Builds and publishes the Docker image to GitHub Container Registry
- Only runs on pushes to master or tags
- Creates appropriate tags including latest, branch name, and version tags

### 4. Release Creation (`release.yml`)
- Creates GitHub releases when tags are pushed
- Generates a changelog from commit messages
- Provides Docker image information in the release notes

## Fixing Common Issues

### Clippy Issues

The Clippy workflow distinguishes between three types of issues:

1. **Compilation Errors**: 
   - These are syntax errors, type errors, etc. that prevent the code from compiling
   - These will cause the build to fail
   - Example: Using an undefined variable, mismatched types

2. **Clippy Errors**:
   - These are serious issues found by Clippy that will cause the build to fail
   - Usually related to correctness or safety concerns
   - Example: Dereferencing raw pointers, incorrect mutex usage

3. **Clippy Warnings**:
   - These are style issues, potential inefficiencies, or code smells
   - These will NOT cause the build to fail
   - Example: Unused imports, unused variables, redundant patterns

### Common Clippy Warnings (Build Will Pass)

- Unused imports
- Unused variables
- Dead code (unused functions)
- Redundant patterns
- Non-snake case variable names
- Implementing `ToString` directly instead of `Display`

### Format Issues

If format check fails, run `cargo fmt` locally before committing your changes.

## Troubleshooting CI Failures

### Clippy Workflow States

The Clippy workflow now has different states with clear icons in PR comments:

1. **✅ Clippy Analysis Passed**: No issues found
2. **⚠️ Clippy Found Warnings (Build Passed)**: Some warnings found, but the build passes
3. **❌ Clippy Found Errors**: Clippy found serious issues that must be fixed (build fails)
4. **❌ Compilation Failed**: The code doesn't compile at all (build fails)

### Fixing Code That Doesn't Compile

If you see a "Compilation Failed" message:

1. Look at the error messages in the PR comment
2. Fix the syntax errors, type errors, or other compilation issues
3. Push the changes to your branch
4. The workflow will run again

### Differences Between Local and CI Clippy Results

Local and CI Clippy runs might show different results because:

1. Different Rust/Clippy versions - ensure your local toolchain matches CI
2. Different feature flags - make sure you're running Clippy with the same features locally

To replicate CI environment locally, run:

```bash
# First check if the code compiles
cargo check --all-targets --all-features

# Then run Clippy
cargo clippy --all-targets --all-features
``` 