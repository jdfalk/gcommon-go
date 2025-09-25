# gcommon-go

Go SDK for gcommon protocol buffers with shared utilities and helper functions

## Overview

This repository provides GO bindings and utilities for the gcommon protocol buffer definitions. It automatically synchronizes with the main [gcommon](https://github.com/jdfalk/gcommon) repository to ensure protocol buffer definitions are always up to date.

## Features

- **Automated Protocol Buffer Sync**: Automatically pulls latest proto definitions from gcommon
- **Strict Version Synchronization**: Ensures version compatibility across all gcommon repositories
- **Shared Utilities**: Common helper functions and business logic implementations
- **CI/CD Integration**: Automated building, testing, and releasing
- **Documentation**: Comprehensive API documentation and examples

## Installation

### Using the Generated Code

```bash
go get github.com/jdfalk/gcommon-go
```

### Development Setup

```bash
git clone https://github.com/jdfalk/gcommon-go.git
cd gcommon-go
make setup
```

## Usage

See the [examples](examples/) directory for comprehensive usage examples.

## Version Synchronization

This repository maintains strict version synchronization with:
- [gcommon](https://github.com/jdfalk/gcommon) - Protocol buffer definitions
- [gcommon-go](https://github.com/jdfalk/gcommon-go) - Go SDK
- [gcommon-py](https://github.com/jdfalk/gcommon-py) - Python SDK

Version updates are automatically triggered when the gcommon repository releases new versions.

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
