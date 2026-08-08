package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// runHealth reports the bridge's health, build version and Stellar network.
// All three endpoints are unauthenticated, so this works before logging in —
// it is the quickest way to check that --endpoint points somewhere real.
//
// It exits non-zero when the bridge reports itself degraded, so it can gate a
// deployment script.
func (a *App) runHealth(opts options, args []string) int {
	fs := a.newFlagSet("health")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("health takes no positional arguments")
	}

	c, err := a.newClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	ctx := context.Background()

	health, healthRaw, err := c.Health(ctx)
	if err != nil {
		return a.fail("health: %v", err)
	}
	// Version and network are informational: report what they say, but don't
	// fail the check if an older bridge doesn't serve them.
	version, versionRaw, versionErr := c.Version(ctx)
	network, networkRaw, networkErr := c.Network(ctx)

	if opts.json {
		combined := map[string]json.RawMessage{"health": healthRaw}
		if versionErr == nil {
			combined["version"] = versionRaw
		}
		if networkErr == nil {
			combined["network"] = networkRaw
		}
		encoded, err := json.MarshalIndent(combined, "", "  ")
		if err != nil {
			return a.fail("encode response: %v", err)
		}
		fmt.Fprintln(a.out, string(encoded))
		return healthExit(health.Status)
	}

	a.render(opts, healthRaw, func(w io.Writer) {
		rows := [][2]string{
			{"Endpoint:", c.Endpoint()},
			{"Status:", health.Status},
			{"Database:", health.Database},
			{"Redis:", health.Redis},
			{"Stellar network:", health.StellarNetwork},
		}
		if versionErr == nil {
			rows = append(rows,
				[2]string{"Bridge version:", fmt.Sprintf("%s %s", version.Name, version.Version)},
				[2]string{"Built:", version.BuildDate},
				[2]string{"Schema version:", str(version.SchemaVersion)},
			)
		}
		if networkErr == nil {
			rows = append(rows,
				[2]string{"Horizon:", network.StellarHorizonURL},
				[2]string{"Soroban RPC:", network.StellarRPCURL},
			)
			if network.SorobanContractID != "" {
				rows = append(rows, [2]string{"Contract id:", network.SorobanContractID})
			}
		}
		kv(w, rows)
	})
	return healthExit(health.Status)
}

func healthExit(status string) int {
	if status == "healthy" {
		return 0
	}
	return 1
}
