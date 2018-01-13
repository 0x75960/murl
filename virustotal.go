package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

var VTS VirusTotal

// VirusTotal record
type VirusTotal struct {
	apikey string
}

// Positives record
type Positives struct {
	Positives    int `json:"positives"`
	ResponseCode int `json:"response_code"`
}

// GetFileReport of specified hash
func (vt VirusTotal) GetFileReport(hash string) (report Positives, err error) {

	u := "https://www.virustotal.com/vtapi/v2/file/report"
	values := url.Values{}

	values.Add("apikey", vt.apikey)
	values.Add("resource", hash)

	resp, err := http.PostForm(u, values)
	if err != nil {
		return report, err
	}

	if resp.StatusCode != 200 {
		return report, fmt.Errorf("VirusTotal returns %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&report)

	if report.ResponseCode != 1 {
		return report, fmt.Errorf("%s not found on VirusTotal", hash)
	}

	return
}
