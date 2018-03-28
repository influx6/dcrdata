package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/josephburnett/jd/lib"
)

var (
	// ErrNoData is returned when giving response contains no data.
	ErrNoData = errors.New("no data received")
)

var (
	nontlsClient = http.Client{Timeout: 10 * time.Second}
	tlsClient    = http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
)

var (
	configFile string
	format     string
)

type result struct {
	From    string
	Against string
	Diff    []byte
	Err     error
}

type opReq struct {
	Path string `json:"path"`
}

type op struct {
	From    string  `json:"from"`
	Against string  `json:"against"`
	Tests   []string `json:"tests"`
}

func main() {
	flag.StringVar(&format, "format", "text", "format to print result in, text or json")
	flag.StringVar(&configFile, "config", "", "config file to use for tests")
	flag.Parse()

	cfile, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("config file %+q not found: %+s", configFile, err)
	}

	defer cfile.Close()

	var config op
	if err := json.NewDecoder(cfile).Decode(&config); err != nil {
		log.Fatalf("failed to parse config file:  %+s", err)
	}

	config.From = strings.TrimSuffix(config.From, "/")
	config.Against = strings.TrimSuffix(config.Against, "/")

	var results []result

	// Run through checks and save results.
	for _, path := range config.Tests {
		path = strings.TrimPrefix(path, "/")
		fromPath := fmt.Sprintf("%s/%s", config.From, path)
		againstPath := fmt.Sprintf("%s/%s", config.Against, path)

		diff, err := verifyRequestResponse(context.TODO(), fromPath, againstPath)
		results = append(results, result{
			From:    fromPath,
			Against: againstPath,
			Diff:    diff,
			Err:     err,
		})
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stderr)
		encoder.SetIndent("\t", "\n")
		if err := encoder.Encode(results); err != nil {
			log.Fatal(err)
		}
	default:
		for _, res := range results {
			if res.Err != nil {
				fmt.Printf("✕ From: %q\n Against: %q\n Failed:%+q\n\n", res.From, res.Against, res.Err.Error())
				continue
			}

			if len(res.Diff) != 0 {
				fmt.Printf("✕ From: %q\n Against: %q\n Diff:\n%+s\n\n", res.From, res.Against, res.Diff)
			}

			fmt.Printf("✔ From: %q\n Against: %q\n\n", res.From, res.Against)
		}
	}
}

type urlError struct{
	Err error
	Target string
}

func (u urlError) Error() string {
	return "URL: "+u.Target+ " Error: "+u.Err.Error()
}

// VerifyRequestResponse attempts to verify the json response received from
// both endpoints to be the same.
func verifyRequestResponse(ctx context.Context, from string, against string) ([]byte, error) {
	fromURL, err := url.Parse(from)
	if err != nil {
		return nil, urlError{Err: err, Target:from}
	}

	fromJSON, err := readJSON(ctx, fromURL)
	if err != nil {
		return nil, urlError{Err: err, Target:from}
	}

	parsedFromData, err := jd.ReadJsonString(string(fromJSON))
	if err != nil {
		return nil, urlError{Err: err, Target:from}
	}

	againstURL, err := url.Parse(against)
	if err != nil {
		return nil, urlError{Err: err, Target:against}
	}

	againstJSON, err := readJSON(ctx, againstURL)
	if err != nil {
		return nil, urlError{Err: err, Target:against}
	}

	parsedAgainstData, err := jd.ReadJsonString(string(againstJSON))
	if err != nil {
		return nil, urlError{Err: err, Target:against}
	}

	return []byte(parsedFromData.Diff(parsedAgainstData).Render()), nil
}

func readJSON(ctx context.Context, path *url.URL) ([]byte, error) {
	if path.Scheme == "" {
		path.Scheme = "http"
	}

	req, err := http.NewRequest("GET",path.String(),  nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	var res *http.Response

	if path.Scheme == "https" {
		res, err = tlsClient.Do(req)
		if err != nil {
			return nil, err
		}
	} else {
		res, err = nontlsClient.Do(req)
		if err != nil {
			return nil, err
		}
	}

	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 204 {
		return nil, fmt.Errorf("request failed with status %d (%s)", res.StatusCode, res.Status)
	}

	var body bytes.Buffer
	n, err := io.Copy(&body, res.Body)
	if err != nil {
		return nil, err
	}

	if n == 0 {
		return nil, ErrNoData
	}

	return body.Bytes(), nil
}
