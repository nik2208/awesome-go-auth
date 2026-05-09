# Contributing to awesome-go-auth

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs
Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) template. Include:
- Go version and OS
- Minimal reproduction case
- Expected vs actual behavior

### Requesting Features
Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) template.

### Submitting Pull Requests

1. Fork the repository
2. Create a branch: `git checkout -b feat/my-feature` or `fix/my-bug`
3. Write your code following the existing style
4. Add or update tests for your changes
5. Run `go test ./...` to ensure all tests pass
6. Run `go vet ./...` for static analysis
7. Submit a pull request using the PR template

### Code Style

- Follow standard Go idioms (gofmt, go vet)
- Keep functions small and focused
- Use table-driven tests
- Prefer interface-based design (no concrete store dependencies in core)
- No CGo — CGO_ENABLED=0 must work
- No external dependencies in core package (stdlib only, except golang.org/x/crypto for bcrypt)

### Adding a New Auth Feature

1. Define the store interface in `store.go`
2. Add the service method in `service.go`
3. Add an in-memory implementation in `memory_store.go` or `feature_stores.go`
4. Update `README.md` Parity Snapshot table
5. Add tests in `service_test.go` or `*_test.go`

### Implementing a Database Adapter

Create a separate repository or contrib folder implementing the store interfaces:
```go
type MyPostgresUserStore struct{ db *pgxpool.Pool }
func (s *MyPostgresUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// ...etc
```

## Development Setup

```bash
git clone https://github.com/nik2208/awesome-go-auth
cd awesome-go-auth
go mod tidy
go test ./...
```

## License

By contributing, you agree your contributions will be licensed under the MIT License.
