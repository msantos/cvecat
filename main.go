// MIT License
//
// Copyright (c) 2019-2021 Michael Santos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type argvT struct {
	cve     []string
	format  string
	dryrun  bool
	verbose int
}

const (
	cvecatVersion = "0.3.1"
)

var (
	errNoDescr          = errors.New("no description")
	errInvalidCVE       = errors.New("invalid CVE")
	errInvalidCVEPrefix = errors.New("invalid CVE prefix")
	errInvalidCVEYear   = errors.New("invalid CVE year")
	errInvalidCVEID     = errors.New("invalid CVE identifier")
)

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

func args() *argvT {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, `%s v%s
  Usage: %s [<option>] <CVE> <...>

`, path.Base(os.Args[0]), cvecatVersion, os.Args[0])
		flag.PrintDefaults()
	}

	dryrun := flag.Bool("dryrun", false, "Do not download")

	format := flag.String(
		"format",
		getenv(
			"CVECAT_FORMAT",
			`*{{.CveDataMeta.ID}}*: {{ (index .Description.DescriptionData 0).Value}}
`,
		),
		"Output template",
	)

	verbose := flag.Int("verbose", 0, "Enable debug messages")
	help := flag.Bool("help", false, "Display usage")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(1)
	}

	return &argvT{
		cve:     flag.Args(),
		format:  *format,
		dryrun:  *dryrun,
		verbose: *verbose,
	}
}

func main() {
	argv := args()

	var r io.Reader = os.Stdin

	if len(argv.cve) > 0 {
		r = strings.NewReader(strings.Join(argv.cve, "\n"))
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		cve := strings.TrimSpace(scanner.Text())
		if cve == "" {
			continue
		}
		buf, err := argv.run(cve)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			continue
		}
		if len(buf) > 0 {
			fmt.Printf("%s", buf)
		}
	}

	if scanner.Err() != nil {
		fmt.Fprintln(os.Stderr, "error:", scanner.Err())
	}
}

func (argv *argvT) run(cve string) ([]byte, error) {
	url, err := geturl(cve)
	if err != nil {
		if argv.verbose > 0 {
			fmt.Fprintf(os.Stderr, "error: %s: %v: format is CVE-<YYYY>-<NNNN...>\n",
				cve, err)
		}
		return []byte{}, nil
	}
	if argv.verbose > 1 {
		fmt.Fprintln(os.Stderr, url)
	}
	if argv.dryrun {
		return []byte{}, nil
	}
	return argv.cat(url)
}

func (argv *argvT) cat(url string) ([]byte, error) {
	body, err := read(url)
	if err != nil {
		return body, err
	}
	if len(body) == 0 {
		return body, nil
	}
	if argv.verbose > 2 {
		fmt.Fprintf(os.Stderr, "%s", body)
	}
	c := &cveJSON4{}
	if err := json.Unmarshal(body, c); err != nil {
		return body, err
	}
	if argv.verbose > 3 {
		fmt.Fprintf(os.Stderr, "%+v", c)
	}
	if len(c.Description.DescriptionData) == 0 {
		return body, errNoDescr
	}
	b, err := format(argv.format, c)
	if err != nil {
		return b, err
	}
	return b, nil
}

func read(url string) ([]byte, error) {
	if url == "-" {
		return ioutil.ReadAll(os.Stdin)
	}
	// #nosec G107
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(
			"%d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}
	return body, err
}

func geturl(id string) (string, error) {
	if id == "-" {
		return "-", nil
	}
	prefix, year, ref, err := parseID(id)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"https://raw.githubusercontent.com/CVEProject/cvelist/master/%s/%sxxx/%s-%s-%s.json",
		year,
		ref[0:len(ref)-3],
		prefix, year, ref,
	), nil
}

func parseID(id string) (prefix, year, ref string, err error) {
	prefix = "CVE"
	p := strings.Split(id, "-")
	switch len(p) {
	case 1:
		now := time.Now()
		ref = p[0]
		year = strconv.Itoa(now.Year())
	case 2:
		ref = p[1]
		year = p[0]
	case 3:
		ref = p[2]
		year = p[1]
		prefix = strings.ToUpper(p[0])
	default:
		return prefix, year, ref, errInvalidCVE
	}
	if len(ref) < 4 {
		ref = strings.Repeat("0", 4-len(ref)) + ref
	}
	if prefix != "CVE" {
		return prefix, year, ref, errInvalidCVEPrefix
	}
	if ok, err := regexp.MatchString("^[0-9]{4}$", year); !ok || err != nil {
		return prefix, year, ref, errInvalidCVEYear
	}
	if ok, err := regexp.MatchString(
		"^[0-9][0-9][0-9][0-9]+$",
		ref,
	); !ok || err != nil {
		return prefix, year, ref, errInvalidCVEID
	}
	return prefix, year, ref, nil
}

func format(fmt string, cve *cveJSON4) ([]byte, error) {
	tmpl, err := template.New("format").Parse(fmt)
	if err != nil {
		return []byte{}, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cve); err != nil {
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}
