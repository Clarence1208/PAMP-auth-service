# CI/CD Workflows

This directory contains GitHub Actions workflows for continuous integration and deployment of the PAMP Auth Service.

## Workflows

### 1. Format Check (`format.yml`)
- Checks that all Rust code follows standard formatting rules using `rustfmt`
- Runs on all PRs and pushes to master
- Will fail if any code doesn't match the standard Rust format

### 2. Tests (`test.yml`)
- Runs all tests with a PostgreSQL database
- Configured with test environment variables
- Runs on all PRs and pushes to master

### 3. Clippy Analysis (`clippy.yml`) 
- Performs code analysis with Clippy to find issues
- Generates a report and comments on PRs with the results
- Formatted to show only relevant error information without dependency noise
- Runs on all PRs and pushes to master

### 4. Docker Build (`build.yml`)
- Builds and publishes the Docker image to GitHub Container Registry
- Only runs on pushes to master or tags
- Creates appropriate tags including latest, branch name, and version tags

### 5. Release Creation (`release.yml`)
- Creates GitHub releases when tags are pushed
- Generates a changelog from commit messages
- Provides Docker image information in the release notes

## Fixing Common Issues

### Clippy Issues

If Clippy reports issues in your PR:

1. **Dead Code**: Functions that are never used. Either:
   - Remove the unused function
   - Add `#[allow(dead_code)]` attribute to functions that are intended for future use

2. **Trait Implementation Issues**: Issues like implementing `ToString` directly:
   ```rust
   // Instead of this:
   impl ToString for MyType { ... }
   
   // Prefer this:
   impl std::fmt::Display for MyType {
       fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
           write!(f, "{}", self.to_string_impl())
       }
   }
   ```

### Format Issues

If format check fails, run `cargo fmt` locally before committing your changes. 