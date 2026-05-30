# Security Policy

## Scope

`keychainbreaker` is an offensive-security / digital-forensics tool: parsing and
decrypting macOS Keychain files is its intended function, not a vulnerability.
Reports about the tool *working as designed* are out of scope.

In scope are defects in this codebase that could harm a legitimate user — for
example a parser bug that lets a crafted `.keychain-db` file cause a crash, a
panic in library code (the library is `panic`-free by contract), or a
memory-safety issue (the crate is `#![forbid(unsafe_code)]`, so any such finding
is high priority).

## Reporting a Vulnerability

Please report privately via GitHub's **"Report a vulnerability"** button under
the repository's *Security* tab, rather than opening a public issue.

Include the affected version, a description, and a minimal reproduction if you
have one. You can expect an initial response within a few days.

## Supported Versions

Security fixes target the latest released `0.x` line.
