package dns

import (
	"net"
	"os"
	"strings"
)

func isFirstLabelShortName(fqdn string, shortName string) bool {
	if firstLabel, _, ok := strings.Cut(fqdn, "."); ok {
		return strings.EqualFold(firstLabel, shortName)
	}

	return false
}

func GetFQDN() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	if strings.Contains(hostname, ".") {
		return hostname, nil
	}

	// 1. Try CNAME lookup. In many configurations, this returns the FQDN if the
	// resolver is configured to search domains.
	if cname, err := net.LookupCNAME(hostname); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if isFirstLabelShortName(cname, hostname) {
			return cname, nil
		}
	}

	// 2. Try reverse lookup of all IPs returned by hostname lookup.
	addrs, err := net.LookupIP(hostname)
	if err == nil {
		for _, addr := range addrs {
			names, err := net.LookupAddr(addr.String())
			if err == nil {
				for _, name := range names {
					name = strings.TrimSuffix(name, ".")
					if isFirstLabelShortName(name, hostname) {
						return name, nil
					}
				}
			}
		}
	}

	// 3. Try reverse lookup of all interface IPs.
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && !ip.IsLoopback() {
					names, err := net.LookupAddr(ip.String())
					if err == nil {
						for _, name := range names {
							name = strings.TrimSuffix(name, ".")
							if isFirstLabelShortName(name, hostname) {
								return name, nil
							}
						}
					}
				}
			}
		}
	}

	// 4. Return the hostname as-is. :-(
	return hostname, nil
}
