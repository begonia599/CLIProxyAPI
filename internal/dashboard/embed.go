// Package dashboard embeds static web assets for CLIProxyAPI dashboards.
package dashboard

import "embed"

//go:embed antigravity_dashboard.html
var Assets embed.FS
