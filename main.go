package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// argvT : command line arguments
type argvT struct {
	cve     []string
	format  string
	dryrun  bool
	verbose int
}

const (
	cvecatVersion = "0.3.0"
)

var stderr = log.New(os.Stderr, "", 0)

func args() *argvT {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, `%s v%s
  Usage: %s [<option>] <CVE> <...>

`, path.Base(os.Args[0]), cvecatVersion, os.Args[0])
		flag.PrintDefaults()
	}

	formatDefault := os.Getenv("CVECAT_FORMAT")
	if formatDefault == "" {
		formatDefault =
			`*{{.CveDataMeta.ID}}*: {{ (index .Description.DescriptionData 0).Value}}
`
	}

	dryrun := flag.Bool("dryrun", false, "Do not download")
	format := flag.String("format", formatDefault, "Output template")
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

	if len(argv.cve) > 0 {
		for _, cve := range argv.cve {
			run(argv, cve)
		}
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cve := scanner.Text()
		if strings.TrimSpace(cve) == "" {
			continue
		}
		run(argv, cve)
	}

	if scanner.Err() != nil {
		stderr.Println("error: ", scanner.Err())
	}
}

func run(argv *argvT, cve string) {
	url, err := geturl(cve)
	if err != nil {
		if argv.verbose > 0 {
			stderr.Printf("error: %s: %v: format is CVE-<YYYY>-<NNNN...>\n",
				cve, err)
		}
		return
	}
	if argv.verbose > 1 {
		stderr.Println(url)
	}
	if argv.dryrun {
		return
	}
	if err := cat(argv, url); err != nil {
		stderr.Printf("error: %s: %v\n", cve, err)
	}
}

func cat(argv *argvT, url string) error {
	body, err := read(url)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	if argv.verbose > 2 {
		stderr.Printf("%s", body)
	}
	c := &cveJSON4{}
	if err := json.Unmarshal(body, c); err != nil {
		stderr.Fatalln("error:", url, ":", err)
	}
	if argv.verbose > 3 {
		stderr.Printf("%+v", c)
	}
	if len(c.Description.DescriptionData) == 0 {
		return errors.New("no description")
	}
	if err := formatCVE(argv.format, c); err != nil {
		return err
	}
	return nil
}

func read(url string) (body []byte, err error) {
	if url == "-" {
		body, err = ioutil.ReadAll(os.Stdin)
		return body, err
	}
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
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
	prefix, year, ref, err := parseid(id)
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

func parseid(id string) (prefix, year, ref string, err error) {
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
		return prefix, year, ref, errors.New("invalid CVE")
	}
	if len(ref) < 4 {
		ref = strings.Repeat("0", 4-len(ref)) + ref
	}
	if prefix != "CVE" {
		return prefix, year, ref, errors.New("invalid CVE prefix")
	}
	if ok, err := regexp.MatchString("^[0-9]{4}$", year); !ok || err != nil {
		return prefix, year, ref, errors.New("invalid CVE year")
	}
	if ok, err := regexp.MatchString(
		"^[0-9][0-9][0-9][0-9]+$",
		ref,
	); !ok || err != nil {
		return prefix, year, ref, errors.New("invalid CVE identifier")
	}
	return prefix, year, ref, nil
}

func formatCVE(format string, cve *cveJSON4) error {
	tmpl, err := template.New("format").Parse(format)
	if err != nil {
		return err
	}

	stdout := bufio.NewWriter(os.Stdout)
	if err := tmpl.Execute(stdout, cve); err != nil {
		return err
	}
	if err := stdout.Flush(); err != nil {
		return err
	}
	return nil
}
