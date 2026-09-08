module impalactl

// This patch version is the module's Go standard-library vulnerability
// pin: CI's setup-go installs exactly what this line names (go-version-file
// in .github/workflows/impalactl.yml), so a directive that lags the current
// patch release makes govulncheck report every stdlib advisory fixed since.
// Keep it in step with lumencli/go.mod.
go 1.26.6

require golang.org/x/term v0.45.0

require golang.org/x/sys v0.47.0 // indirect
