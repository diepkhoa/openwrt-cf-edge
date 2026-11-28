package notify

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// FormatDDNSUpdate builds a clean HTML alert for updated Cloudflare DNS records,
// grouping multiple record types per subdomain (e.g. "test.com (A, AAAA)").
func FormatDDNSUpdate(nodeName, ipv4, ipv6 string, updated []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🌐 <b>[cf-edge] DDNS Updated</b> — <code>%s</code>\n", html.EscapeString(nodeName))
	if ipv4 != "" {
		fmt.Fprintf(&b, "• <b>IPv4:</b> <code>%s</code>\n", html.EscapeString(ipv4))
	}
	if ipv6 != "" {
		fmt.Fprintf(&b, "• <b>IPv6:</b> <code>%s</code>\n", html.EscapeString(ipv6))
	}

	hosts := groupUpdatedHosts(updated)
	switch len(hosts) {
	case 0:
	case 1:
		fmt.Fprintf(&b, "• <b>Host:</b> <code>%s</code>", html.EscapeString(hosts[0]))
	default:
		b.WriteString("• <b>Hosts:</b>\n")
		for _, h := range hosts {
			fmt.Fprintf(&b, "  • <code>%s</code>\n", html.EscapeString(h))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func groupUpdatedHosts(entries []string) []string {
	type hostGroup struct {
		name  string
		types map[string]struct{}
	}
	var order []string
	groups := make(map[string]*hostGroup)

	for _, raw := range entries {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		host := s
		var recTypes []string
		if idx := strings.LastIndex(s, " ("); idx > 0 && strings.HasSuffix(s, ")") {
			host = strings.TrimSpace(s[:idx])
			typeList := s[idx+2 : len(s)-1]
			for _, part := range strings.Split(typeList, ",") {
				t := strings.ToUpper(strings.TrimSpace(part))
				if t != "" {
					recTypes = append(recTypes, t)
				}
			}
		}
		g, ok := groups[host]
		if !ok {
			g = &hostGroup{name: host, types: make(map[string]struct{})}
			groups[host] = g
			order = append(order, host)
		}
		for _, t := range recTypes {
			g.types[t] = struct{}{}
		}
	}

	out := make([]string, 0, len(order))
	for _, host := range order {
		g := groups[host]
		if len(g.types) == 0 {
			out = append(out, host)
			continue
		}
		types := make([]string, 0, len(g.types))
		for t := range g.types {
			types = append(types, t)
		}
		// Sort so "A" precedes "AAAA", then alphabetical for any other types.
		sort.Slice(types, func(i, j int) bool {
			if types[i] == "A" && types[j] != "A" {
				return true
			}
			if types[j] == "A" && types[i] != "A" {
				return false
			}
			return types[i] < types[j]
		})
		out = append(out, fmt.Sprintf("%s (%s)", host, strings.Join(types, ", ")))
	}
	return out
}

// FormatPPPoEAction builds an HTML alert for PPPoE Guard recovery events.
func FormatPPPoEAction(nodeName, action, detail string) string {
	return fmt.Sprintf(
		"🔌 <b>[cf-edge] PPPoE Guard</b> — <code>%s</code>\n• <b>Action:</b> <code>%s</code>\n• <b>Detail:</b> %s",
		html.EscapeString(nodeName),
		html.EscapeString(action),
		html.EscapeString(detail),
	)
}

// FormatShieldEntered builds an HTML alert when entering DDoS Shield mode.
func FormatShieldEntered(nodeName, reason, newIP, workerStatus string) string {
	return fmt.Sprintf(
		"🛡️ <b>[cf-edge] DDoS SHIELD ENTERED</b> — <code>%s</code>\n• <b>Reason:</b> <code>%s</code>\n• <b>New WAN IP:</b> <code>%s</code>\n• <b>Worker:</b> %s",
		html.EscapeString(nodeName),
		html.EscapeString(reason),
		html.EscapeString(newIP),
		html.EscapeString(workerStatus),
	)
}

// FormatShieldExited builds an HTML alert when exiting DDoS Shield mode.
func FormatShieldExited(nodeName, detail string) string {
	return fmt.Sprintf(
		"✅ <b>[cf-edge] DDoS Shield Exited</b> — <code>%s</code>\n• <b>Status:</b> %s",
		html.EscapeString(nodeName),
		html.EscapeString(detail),
	)
}

// FormatAutoUpdate builds an HTML alert when a scheduled binary update succeeds.
func FormatAutoUpdate(nodeName, fromVersion, toVersion string, restarting bool) string {
	action := "binary updated"
	if restarting {
		action = "binary updated, restarting service"
	}
	return fmt.Sprintf(
		"🔄 <b>[cf-edge] Auto-Update</b> — <code>%s</code>\n• <b>Version:</b> <code>%s</code> → <code>%s</code>\n• <b>Action:</b> %s",
		html.EscapeString(nodeName),
		html.EscapeString(fromVersion),
		html.EscapeString(toVersion),
		action,
	)
}

// FormatFirewallAlert builds an HTML alert for edge_firewall failures or automatic rollbacks.
func FormatFirewallAlert(nodeName, action, detail string) string {
	return fmt.Sprintf(
		"🔥 <b>[cf-edge] Edge Firewall %s</b> — <code>%s</code>\n• <b>Detail:</b> %s",
		html.EscapeString(action),
		html.EscapeString(nodeName),
		html.EscapeString(detail),
	)
}

// FormatMeshPeerAlert builds an HTML alert when a peer goes OFFLINE or RECOVERS on the NetBird mesh.
func FormatMeshPeerAlert(reporterNode, peerName, peerIP, site, status, detail string) string {
	icon := "🔴"
	if strings.EqualFold(status, "ONLINE") || strings.EqualFold(status, "RECOVERED") {
		icon = "🟢"
	}
	return fmt.Sprintf(
		"%s <b>[cf-edge] Mesh Peer %s</b> — <code>%s</code>\n• <b>Peer IP:</b> <code>%s</code> (<code>%s</code>)\n• <b>Reporter:</b> <code>%s</code>\n• <b>Detail:</b> %s",
		icon,
		html.EscapeString(status),
		html.EscapeString(peerName),
		html.EscapeString(peerIP),
		html.EscapeString(site),
		html.EscapeString(reporterNode),
		html.EscapeString(detail),
	)
}
