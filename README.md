# SYNOPSIS

cvecat [*options*] *CVE-YYYY-NNNN* *...*

# DESCRIPTION

Format and write CVE data to stdout

cvecat takes one or more CVE identifiers as arguments and outputs the
data to standard output.

The CVE data is download from the `cvelist` project on GitHub:

    https://github.com/CVEProject/cvelist

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
FORMAT='ID: {{.CveDataMeta.ID}}
Assigner: {{.CveDataMeta.Assigner}}
'
cvecat --format="$FORMAT" CVE-2019-6013
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

# Alternatives

## shell

```
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

  # https://raw.githubusercontent.com/CVEProject/cvelist/master/2019/10xxx/CVE-2019-10210.json
  URL="https://raw.githubusercontent.com/CVEProject/cvelist/master/$YEAR/${ID%[0-9][0-9][0-9]}xxx/$CVE.json"

  curl -s "$URL"
  IFS="$OFS"
}

for arg in "$@"; do
  cve "$arg" |
    jq -r '.description.description_data[] | select(.lang == "eng") | .value'
done
```
