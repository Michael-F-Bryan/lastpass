# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.0] - 2020-04-12

### Added

- Created functions for accessing API endpoints
  - `login.php` - start a new session
  - `logout.php` - finish a session
  - `login_check.php` - used to fetch the current vault version
  - `getaccts.php` - used to fetch the full vault
  - `getattach.php` - download attachment
  - `iterations.php` - get the number of iterations to use when generating keys
- Created wrappers around a `DecryptionKey` and ` LoginKey`
- Created a `kitchen_sink.rs` example which uses all available endpoints
- We can parse the following items out of an encrypted "blob" (the `Vault`)
  - Accounts
  - Attachment metadata
  - the `is_local` flag
  - the vault version

[Unreleased]: https://github.com/Michael-F-Bryan/lastpass/compare/v0.1.0...master
[v0.1.0]: https://github.com/Michael-F-Bryan/lastpass/compare/initial-commit...v0.1.0
