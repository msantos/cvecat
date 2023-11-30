package cve5

import (
	"strings"
	"time"
)

// Timestamp is an RFC3339 timestamp that may include nanoseconds:
// * 2023-11-17T12:57:41.538666
// * 2023-11-24T19:51:55.099Z
// * 2010-05-24T00:00:00Z
type Timestamp struct {
	time.Time
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	before, _, _ := strings.Cut(strings.TrimSuffix(strings.Trim(string(b), "\""), "Z"), ".")
	x, err := time.Parse("2006-01-02T15:04:05", before)
	if err != nil {
		return err
	}
	t.Time = x
	return nil
}

type CVE struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CveMetadata struct {
		CveID             string    `json:"cveId"`
		AssignerOrgID     string    `json:"assignerOrgId"`
		State             string    `json:"state"`
		AssignerShortName string    `json:"assignerShortName"`
		DateReserved      Timestamp `json:"dateReserved"`
		DatePublished     Timestamp `json:"datePublished"`
		DateUpdated       Timestamp `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna struct {
			Title            string `json:"title"`
			ProviderMetadata struct {
				OrgID       string    `json:"orgId"`
				ShortName   string    `json:"shortName"`
				DateUpdated Timestamp `json:"dateUpdated"`
			} `json:"providerMetadata"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Affected []struct {
				Vendor   string `json:"vendor"`
				Product  string `json:"product"`
				Versions []struct {
					Version     string `json:"version"`
					LessThan    string `json:"lessThan"`
					Status      string `json:"status"`
					VersionType string `json:"versionType"`
				} `json:"versions"`
			} `json:"affected"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Metrics []struct {
				CvssV30 struct {
					Version               string  `json:"version"`
					AttackComplexity      string  `json:"attackComplexity"`
					AttackVector          string  `json:"attackVector"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					IntegrityImpact       string  `json:"integrityImpact"`
					PrivilegesRequired    string  `json:"privilegesRequired"`
					Scope                 string  `json:"scope"`
					UserInteraction       string  `json:"userInteraction"`
					VectorString          string  `json:"vectorString"`
					BaseScore             float64 `json:"baseScore"`
					BaseSeverity          string  `json:"baseSeverity"`
				} `json:"cvssV3_0"`
			} `json:"metrics"`
			ProblemTypes []struct {
				Descriptions []struct {
					Type        string `json:"type"`
					Lang        string `json:"lang"`
					Description string `json:"description"`
					CweID       string `json:"cweId"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			Source struct {
				Advisory  string `json:"advisory"`
				Discovery string `json:"discovery"`
			} `json:"source"`
		} `json:"cna"`
	} `json:"containers"`
}
