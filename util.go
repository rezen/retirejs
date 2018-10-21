package retirejs

import (
	"fmt"
	"os"
	"net"
	"time"
	"strings"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
)

func getTransport() *http.Transport {
	return &http.Transport{
		Dial: (&net.Dialer{
    		Timeout: 3 * time.Second,
  		}).Dial,
  		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 3 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,    
	}
}

func fetchUrl(path string) *http.Response {
	// @todo configure timeout
	timeout := time.Duration(3) * time.Second
	transport := getTransport()

	headers := map[string]string{
		"X-Retirejs": "1",
		"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
		"Cache-Control": "max-age=0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
	}

	cookieJar, _ := cookiejar.New(nil)
	redirects := 0

	client := http.Client{
    	Timeout: timeout,
    	Transport: transport,
    	Jar: cookieJar,
    	CheckRedirect: func(req *http.Request, via []*http.Request) error {
    		redirects += 1
    		if redirects <= 3 {
				for header, value := range headers {
						req.Header.Add(header, value)
					}
					return nil
    		}
      		return http.ErrUseLastResponse
  		},

	}
	request, err := http.NewRequest("GET", path, nil)

	for header, value := range headers {
		request.Header.Add(header, value)
	}

	if err != nil {
		fmt.Println("err", err)
		return &http.Response{}
	}
	response, err := client.Do(request)

	if err != nil {
		fmt.Println("err", err)
		os.Exit(12)
		return &http.Response{}
	}
	return response
}


func getContent(uri string) []byte {
	contents := []byte("")
	if strings.Contains(uri, "://") {
		res := fetchUrl(uri)
		defer res.Body.Close()
		contents, _ = ioutil.ReadAll(res.Body)

	} else {
		content, err := ioutil.ReadFile(uri)

		if err != nil {
			panic(err)
		}

		contents = content
	}

	return contents
}


func FileExists(file string) bool {
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
