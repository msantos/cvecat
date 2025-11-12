[![Go Reference](https://pkg.go.dev/badge/go.iscode.ca/cvecat.svg)](https://pkg.go.dev/go.iscode.ca/cvecat)

# SYNOPSIS

cvecat [*options*] *CVE-YYYY-NNNN* *...*

# DESCRIPTION

A command line utility to format and write CVE data to stdout.

cvecat takes one or more CVE identifiers as arguments and outputs the
data to standard output. If no arguments are provided, cvecat reads the
CVE identifiers from stdin, one per line.

To test formatting, cvecat can read JSON data from stdin by using `-`
as an argument.

The CVE data is download from the `cvelist` project on GitHub:

```
https://github.com/CVEProject/cvelistV5
```

# BUILD

```
go install go.iscode.ca/cvecat@latest
```

* build from git repository

```
CGO_ENABLED=0 go build -trimpath -ldflags "-w" ./cmd/cvecat
```

# EXAMPLES

## Write CVEs to stdout

```
cvecat CVE-2019-5007 CVE-2019-5008 CVE-2019-5009
```

## Read from stdin to stdout

```
cat << EOF | cvecat
CVE-2019-5007
CVE-2019-5008
CVE-2019-5009
EOF
```

## Specify Formatting

```
FORMAT='ID: {{.CVE.CveMetadata.CveID}}
Assigner: {{.CVE.CveMetadata.AssignerShortName}}
'
cvecat --format="$FORMAT" CVE-2019-6013
```

## Test Formatting

```
cat CVE-2019-6013.json | cvecat --format="$FORMAT" -
```

# OPTIONS

--dryrun
: Do not perform any network operations

--format *string*
: Template for formatting output using the [Go template
syntax](https://golang.org/pkg/text/template/)

--verbose *int*
: Enable debug messages. To see the JSON field names for use in the
template, use `verbose=3`.

# ENVIRONMENT VARIABLES

CVECAT_FORMAT
:set default value for --format

## Template Functions

### replace

Replace all occurrences of a regular expression with a string.

```
# Converts a CVE description to a single line
cvecat --format '*{{.CVE.CveMetadata.CveID}}*: {{ replace (index .CVE.Containers.Cna.Descriptions 0).Value "(?m)\n" " " }}
'
```

### mdescape

Escape markdown special characters so the text can be embedded in a
markdown document.

```
#!/bin/sh

set -o errexit

 cat <<'EOF'
| CVE | Description |
| --- | --- |
EOF

# Convert description to a single line and escape | to embed the
# description in a markdown table
cvecat --format '| {{.CVE.CveMetadata.CveID}} | {{ mdescape (replace (index .CVE.Containers.Cna.Descriptions 0).Value "(?m)\n" " ") }} |
'
```

# Alternatives

## shell

```bash
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

cve() {
  CVE="$1"

  OFS="$IFS"
  IFS="-"
  set -- $CVE

  YEAR="$2"
  ID="$3"

  if [ "$1" != "CVE" ]; then
    exit 1
  fi
  if [[ ! "$2" =~ ^[0-9]{4}$ ]]; then
    exit 1
  fi
  if [[ ! "$3" =~ ^[0-9][0-9][0-9][0-9]+$ ]]; then
    exit 1
  fi

  # https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2019/10xxx/CVE-2019-10210.json
  URL="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/$YEAR/${ID%[0-9][0-9][0-9]}xxx/$CVE.json"

  curl -s "$URL"
  IFS="$OFS"
}

for arg in "$@"; do
  cve "$arg" |
    jq -r '.containers.cna.descriptions[] | select(.lang == "en") | .value'
done
```
