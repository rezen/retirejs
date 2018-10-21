package retirejs

import (
	"html/template"
	"sort"
	"bytes"
	"encoding/json"
)


var reportTemplate = `{{range .Blocks}}
## Found issue(s) in asset libraries - {{ len .Vulns}}
**{{.Asset}}**{{with .Vulns}}
{{range .}}
### Library
{{.Library}} {{.Version}} [{{.AtOrAbove}} - {{.Below}}]

### Summary 
{{ index .Identifiers "CVE" }} {{ index .Identifiers "summary" }}

### Severity
{{ .Severity }}

### Info
{{ range .Info }}- {{. }}
{{end}}{{end}}{{end}}{{end}}`

type assetBlock struct {
	Asset string
	Vulns []VulnerabilityMatch
}

type reportData struct {
	Blocks []assetBlock
}

func ReportMarkdown(vulns []VulnerabilityMatch) []byte {
	vulnMap := map[string][]VulnerabilityMatch{}
	assets := []string{}
	for _, vuln := range vulns {
		if _, ok := vulnMap[vuln.Asset]; !ok {
			vulnMap[vuln.Asset] = make([]VulnerabilityMatch, 0)
			assets = append(assets, vuln.Asset)
		}

		vulnMap[vuln.Asset] = append(vulnMap[vuln.Asset], vuln)
	}

	blocks := []assetBlock{}

	sort.Strings(assets)
	for _, asset := range assets {
		vulns := vulnMap[asset]
		blocks = append(blocks, assetBlock{asset, vulns})
	}
	data := new(bytes.Buffer)
	tmpl := template.New("report-default")		
 	tmpl, _ = tmpl.Parse(reportTemplate)
	tmpl.Execute(data, reportData{blocks})
	return data.Bytes()
}

func ReportJson(vulns []VulnerabilityMatch) []byte {
	data := new(bytes.Buffer)
	enc := json.NewEncoder(data)
	enc.SetIndent("", "    ")
	if err := enc.Encode(vulns); err != nil {
    	panic(err)
	}
	return data.Bytes()
}