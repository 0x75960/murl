package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0x75960/dencode"
	"github.com/0x75960/midy"

	"github.com/bradfitz/iter"
	"github.com/fatih/color"
)

var ModeSaveContent = flag.String("s", "", "store result into specified directory")
var ModeLoadContent = flag.String("l", "", "load stored result from specified directory")

// URLDetail record
type URLDetail struct {
	AccessSucceeded bool `toml:"access_succeeded,omitempty"`

	IP     []string `toml:"ip,omitempty"`
	URL    string   `toml:"url,omitempty"`
	Domain string   `toml:"domain,omitempty"`

	Status     string `toml:"status,omitempty"`
	StatusCode int    `toml:"status_code,omitempty"`

	ContentType   string `toml:"content_type,omitempty"`
	ContentSha256 string `toml:"content_sha_256,omitempty"`

	URLDetected     int `toml:"url_detected,omitempty"`
	ContentDetected int `toml:"content_detected,omitempty"`

	RedirectTo string `toml:"redirect_to,omitempty"`
}

// String format interface for "fmt"
func (ud URLDetail) String() (s string) {

	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	if ud.AccessSucceeded == false {
		return fmt.Sprintf("%s %s", red("[ERROR: Unreachable]"), yellow(ud.URL))
	}

	var status string
	switch {
	case ud.StatusCode == 200:
		status = green(ud.Status)
	case 300 <= ud.StatusCode && ud.StatusCode < 400:
		status = yellow(ud.Status)
	default:
		status = red(ud.Status)
	}

	u := ud.URL
	if ud.URLDetected != 0 {
		u = red(
			ud.URL + fmt.Sprintf(" [VT: %d]", ud.URLDetected),
		)
	}

	s256 := ud.ContentSha256

	switch {
	case ud.ContentDetected != 0:
		s256 = red(
			s256 + fmt.Sprintf(" [VT: %d]", ud.ContentDetected),
		)
	case midy.EmptyHash(ud.ContentSha256):
		s256 = green(
			"<empty>",
		)
	default:
	}

	mimetype := ud.ContentType

	switch mimetype {
	case "application/octet-stream":
		fallthrough
	case "application/java-archive":
		fallthrough
	case "application/x-shockwave-flash":
		fallthrough
	case "application/x-msdownload":
		fallthrough
	case "application/x-msdos-program":
		mimetype = yellow(mimetype)
	}

	var ip string
	if len(ud.IP) != 0 {
		ip = ud.IP[0]
	}

	for _, i := range ud.IP {
		if strings.Contains(i, ".") {
			ip = i
			break
		}
	}

	return fmt.Sprintf("[%s] <%s> %s [%s] => %s", status, ip, u, mimetype, s256)
}

// Traced Result
type Traced struct {
	Date    time.Time   `toml:"traced_at"`
	Details []URLDetail `toml:"details"`
}

// String formatter for Traced
func (t Traced) String() (s string) {

	cyan := color.New(color.FgCyan).SprintFunc()

	s += fmt.Sprintf("traced at %s\n", cyan(t.Date.Format("2006/01/02 15:04:05 UTC")))

	for idx, item := range t.Details {

		for range iter.N(idx) {
			s += "  "
		}

		s += fmt.Sprintf("%s\n", item)
	}

	return
}

// Store traced result
func (t Traced) Store() (err error) {

	f, err := os.Create(filepath.Join(*ModeSaveContent, "result.toml"))
	if err != nil {
		return err
	}

	defer f.Close()

	dencode.NewEncoder(dencode.TomlFormat, f).Encode(&t)
	return
}

// Load result from stored result
func Load() (t Traced, err error) {
	f, err := os.Open(filepath.Join(*ModeLoadContent, "result.toml"))
	if err != nil {
		return t, err
	}

	defer f.Close()
	dencode.NewDecoder(dencode.TomlFormat, f).Decode(&t)

	return
}

// GetURLDetail of target url
func GetURLDetail(u string) (detail URLDetail, err error) {

	// Basic Informations
	detail.URL = u
	detail.Domain = strings.Split(u, "/")[2]

	// Get IP Address
	addr, err := net.LookupHost(detail.Domain)
	if err != nil {
		detail.AccessSucceeded = false
		return detail, err
	}

	detail.IP = addr

	// Request to URL
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0")

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		detail.AccessSucceeded = false
		return detail, err
	}

	defer resp.Body.Close()

	s256, err := procContent(resp.Body)
	if err != nil {
		log.Println(err)
	}

	detail.ContentSha256 = s256

	// Get Redirect Address
	if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 {
		detail.RedirectTo = resp.Header.Get("Location")
	}

	if *APIKEY != "" {

		if midy.EmptyHash(s256) {

			// if not empty
			cr, err := VTS.GetFileReport(s256)
			if err != nil {
				log.Println("failed to get content report", err)
			}

			detail.ContentDetected = cr.Positives
		}

		p, _ := url.Parse(u)
		ur, err := VT.ReportUrl(p)
		if err != nil {
			log.Println("failed to get url report", err)
		}

		detail.URLDetected = ur.Positives
	}

	// set URL Status
	detail.AccessSucceeded = true
	detail.Status = resp.Status
	detail.StatusCode = resp.StatusCode
	detail.ContentType = resp.Header.Get("Content-Type")

	return
}

func procContent(r io.Reader) (s256 string, err error) {

	hasher := sha256.New()

	if *ModeSaveContent == "" {
		// not specified content save directory
		io.Copy(hasher, r)
		return hex.EncodeToString(hasher.Sum(nil)), nil
	}

	err = os.MkdirAll(
		filepath.Join(*ModeSaveContent, "contents"),
		os.ModePerm,
	)
	if err != nil {
		io.Copy(hasher, r)
		// toriaezu naniga attemo sha256 kaesu
		return hex.EncodeToString(hasher.Sum(nil)), err
	}

	// save content to temppath
	tmppath := filepath.Join(*ModeSaveContent, "contents", "__to_be_renamed__")
	f, err := os.Create(tmppath)
	if err != nil {
		io.Copy(hasher, r)
		// toriaezu naniga attemo sha256 kaesu
		return hex.EncodeToString(hasher.Sum(nil)), err
	}

	// and calc hash at the same time

	w := io.MultiWriter(hasher, f)
	io.Copy(w, r)

	s256 = hex.EncodeToString(hasher.Sum(nil))

	f.Close()

	// rename filename to sha256
	err = os.Rename(tmppath, filepath.Join(*ModeSaveContent, "contents", s256))

	return
}

// GetURLDetails by GET Request to specified url up to maxDepth
func GetURLDetails(url string, maxDepth int) (result Traced, err error) {

	targetURL := url

	result.Date = time.Now().UTC()

	for range iter.N(maxDepth) {

		detail, err := GetURLDetail(targetURL)
		if err != nil {
			log.Println(err)
			result.Details = append(result.Details, detail)
			break
		}

		if detail.RedirectTo != "" && strings.HasPrefix(detail.RedirectTo, "http") == false {
			// FIXME: make this better
			items := strings.Split(targetURL, "/")
			items[len(items)-1] = detail.RedirectTo
			detail.RedirectTo = strings.Join(items, "/")
		}

		result.Details = append(result.Details, detail)
		if detail.RedirectTo == "" {
			break
		}

		targetURL = detail.RedirectTo

		<-time.After(1 * time.Second)
	}

	return
}

func Normalize(u string) (targetURL string) {

	targetURL = u

	if strings.HasPrefix(targetURL, "hxxp") {
		targetURL = strings.Replace(targetURL, "hxxp", "http", 1)
	}

	if strings.HasPrefix(targetURL, "http") == false {
		targetURL = fmt.Sprintf("http://%s", targetURL)
	}

	targetURL = strings.Replace(targetURL, "[.]", ".", -1)
	targetURL = strings.Replace(targetURL, `\.`, ".", -1)

	return
}
