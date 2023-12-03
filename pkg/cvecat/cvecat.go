package cvecat

import "codeberg.org/msantos/cvecat/pkg/cve5"

type Data struct {
	URL     string
	Version string
	CVE     cve5.CVE
}
