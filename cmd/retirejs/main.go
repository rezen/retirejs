package main

import (
	"os"
	"time"
	"github.com/rezen/retirejs"
	"encoding/json"
	"fmt"
	"sync"
	"strings"
	"path"
)

func main() {
	start := time.Now()
	target := ""
	printJson := false
	if len(os.Args) > 1 {
		target = os.Args[1]
	}


	for _, value := range os.Args {
		if value == "--json" {
			printJson = true
		}
	}

	if target == "" {
		fmt.Println("[i] Provide a first param")
		fmt.Println(" - retirejs http://example.com")
		fmt.Println(" - retirejs ~/vcs/test")
		os.Exit(2)
	}

	var wg sync.WaitGroup
	var scripts []string
	repo := retirejs.GetRepository()
	findings := []retirejs.LibraryFinding{}

	if strings.Contains(target, "://") {
		fmt.Println("[i] Target is a url", target)
		// If a direct script is provided ...
		if strings.Contains(path.Base(target), ".js") {
			scripts = append(scripts, target)
		} else {
			scripts = retirejs.ExtractScripts(target)
		}
	} else {
		if  !retirejs.FileExists(target) {
			fmt.Println("[!] That path does not exist")
			os.Exit(2)
		}
		fmt.Println("[i] Target is file path", target)
		scripts = retirejs.FindScripts(target)
	}

	fmt.Println("[i] Found scripts to inspect -", len(scripts))
	for _, script := range scripts {
		fmt.Println(" - ", script)
	}
	fmt.Println()
	wg.Add(len(scripts))
	for _, script := range scripts {
		go func(script string) {
			found := retirejs.CheckJavascript(repo, script)
			for _, item := range found {
				findings = append(findings, item)
			}
			wg.Done()
		}(script)
	}

	wg.Wait()

	vulns := retirejs.EvaluateFindings(findings)
	duration := time.Since(start)
	fmt.Println("[i] Ran for ", duration)

	if len(vulns) == 0 {
		fmt.Println("[i] Clean!")
		os.Exit(0)
		return
	}

	fmt.Println("[!] Number of vulns", len(vulns))

	if printJson {
		fmt.Println("-------------------------------------------------")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "    ")
		if err := enc.Encode(vulns); err != nil {
	    	panic(err)
		}
		os.Exit(1)
	}

	retirejs.PrintVulns(vulns)

	
	os.Exit(1)
}
