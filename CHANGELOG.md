# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).



## [1.1.0] - 2025-08-29
### Added
- Framework adapter support:
  - Django adapter
  - Flask adapter  
  - FastAPI adapter
- Enhanced validation modes (STRICT, LAX and PERMISSIVE)
- Comprehensive test suite for individual gateway adapters

## [1.0.0] - 2025-08-24
### Added
- Initial validation layer with support for:
  - Strict and lax validation modes
  - Pydantic schema enforcement
  - Pluggable error formatter
  - Idempotent request handling
  - Test suite for validation behaviors