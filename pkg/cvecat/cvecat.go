package cvecat

import "go.iscode.ca/cvecat/pkg/cve5"

type Data struct {
	URL     string
	Version string
	CVE     cve5.CVE
}
