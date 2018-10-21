package retirejs

import (
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/mcuadros/go-version"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"regexp"
	"strings"
	"path"
	"sync"
	"crypto/sha1"
	"encoding/hex"
	"log"
	"path/filepath"
	"net/url"
	"sort"
)

var (
	repository Repository
	once sync.Once
)

const (
	MATCH_URI      = 1
	MATCH_CONTENT  = 2
	MATCH_FILENAME = 3
)


type Vulnerability struct {
	Below       string
	AtOrAbove   string
	Severity    string
	Identifiers map[string]interface{}
	Info        []string
}

func (v Vulnerability) IsVulnerableVersion(ver string) bool {
	above := v.AtOrAbove

	if v.AtOrAbove == "" {
		above = "0.0"
	}

	comparator := fmt.Sprintf(">=%v,<%v", above, v.Below)
	compare := version.NewConstrainGroupFromString(comparator)
	return compare.Match(ver)
}


type VulnerabilityMatch struct {
	Vulnerability
	Version   string
	Library   string
	MatchType int
	Asset string
}

func CreateMatch(finding LibraryFinding, vuln Vulnerability) VulnerabilityMatch {
	return VulnerabilityMatch{
		vuln,
		finding.Version,
		finding.Library.Name,
		finding.MatchType,
		finding.Asset,
	}
}

type Extractor struct {
	Func []string
	Uri []string
	Filename []string
	Filecontent []string
	Hashes map[string]string
}

type Library struct {
	Name             string
	Bowername []string
	Extractors       Extractor
	ExtractorRegexps map[string][]*regexp.Regexp
	Vulnerabilities  []Vulnerability
}

type Repository []Library

func (r Repository) IsLibraryVulnerable(library, version string) bool {
	lib, found := r.FindLibrary(library)

	if !found {
		return false
	}

	return lib.IsVulnerableVersion(version)
}


func (r Repository) FindLibrary(lib string) (Library, bool) {
	for _, library := range r {
		if library.IsLibrary(lib) {	
			return library, true
		}
	}
	return Library{}, false
}

func (r Repository) FuncsForDomVersions() (funcs [][]string) {
	for _, library := range r {
		for _, fn := range library.Extractors.Func {
			funcs = append(funcs, []string{library.Name, fn})
		}
	}
	return funcs
}

func (r Repository) CheckUri(uri []byte) []LibraryFinding {
	findings := []LibraryFinding{}
	for _, library := range r {
		version, match := library.MatchesUri(uri)

		if match {
			findings = append(findings, LibraryFinding{
				Library:   library,
				Version:   version,
				MatchType: MATCH_URI,
			})

		}
	}

	return findings
}


func (r Repository) CheckContent(content []byte) []LibraryFinding {
	findings := []LibraryFinding{}
	for _, library := range r {
		version, match := library.MatchesContent(content)

		if match {
			findings = append(findings, LibraryFinding{
				Library:   library,
				Version:   version,
				MatchType: MATCH_CONTENT,
			})
		}
	}

	return findings
}

func (r Repository) CheckFilename(name []byte) []LibraryFinding {
	findings := []LibraryFinding{}
	for _, library := range r {
		version, match := library.MatchesFilename(name)

		if match {
			findings = append(findings, LibraryFinding{
				Library:   library,
				Version:   version,
				MatchType: MATCH_FILENAME,
			})
		}
	}

	return findings
}


func (l Library) IsLibrary(name string) bool {
	// Lowercase the name
	if l.Name == name {
		return true
	}
	for _, n := range l.Bowername {
		if n == name {
			return true
		}
	}
	return false
}

func (l Library) Matches(key string, check []byte) (string, bool) {
	for _, regex := range l.ExtractorRegexps[key] {
		matches := regex.FindAllSubmatch(check, -1)
		if len(matches) == 0 {
			continue
		}

		version := string(matches[0][1])
		version = strings.Replace(version, ".min", " ", -1)

		return version, true
	}

	return "", false
}

func (l Library) MatchesContent(check []byte) (string, bool) {
	return l.Matches("filecontent", check)
}

func (l Library) MatchesUri(check []byte) (string, bool) {
	return l.Matches("uri", check)
}

func (l Library) MatchesFilename(check []byte) (string, bool) {
	return l.Matches("filename", check)
}

func (l Library) IsVulnerableVersion(ver string) bool {
	for _, vuln := range l.Vulnerabilities {
		if vuln.IsVulnerableVersion(ver) {
			return true
		}
	}
	return false
}

type byLibrary []VulnerabilityMatch

func (s byLibrary) Len() int {
    return len(s)
}
func (s byLibrary) Swap(i, j int) {
    s[i], s[j] = s[j], s[i]
}
func (s byLibrary) Less(i, j int) bool {
    return len(s[i].Library) < len(s[j].Library)
}

type LibraryFinding struct {
	Library   Library
	Version   string
	MatchType int
	Match     [][][]byte
	Asset string
}

func fetchRepos() {
	root := GetRoot()
	url := "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
	response := fetchUrl(url)
	defer response.Body.Close()

	out, err := os.Create(path.Join(root, "jsrepository.json"))
	if err != nil {
		panic(err)
	}
	defer out.Close()
	io.Copy(out, response.Body)
}


func GetRoot() string {
	var root string

	if os.Getenv("RETIREJS_ROOT") != "" {
		root = os.Getenv("RETIREJS_ROOT")
	} else {
		usr, _ := user.Current()
		dir := usr.HomeDir
		root = path.Join(dir, "/.retirejs/")
	}
	return root
}


func GetRepoFile() string {
	root := GetRoot()
	filepath := path.Join(root, "jsrepository.json")
	if !FileExists(filepath) {
		// Does not exist ... fetch it
		fetchRepos()
	}
	return filepath
}


func extractorRegexes(patterns []string) ([]*regexp.Regexp) {
	regexes := []*regexp.Regexp{}
	for _, regex := range patterns {
		// Tweak regex since js handles regex differently
		regex = strings.Replace(regex, " *", " \\*", -1)
		expr, err := regexp.Compile(regex)

		if err != nil {
			fmt.Println(err)
			continue
		}
		regexes = append(regexes, expr)
	}
	return regexes
}

func ReadLibraries() []Library {
	var repos map[string]Library
	filepath := GetRepoFile()
	file, _ := os.Open(filepath)
	defer file.Close()

	// @todo can change to strings.ReplaceAll
	fixVersion := regexp.MustCompile("§§version§§")
	fixRepeats := regexp.MustCompile("\\{0,[0-9]{4}\\}")

	data, _ := ioutil.ReadAll(file)
	data = fixVersion.ReplaceAll(data, []byte("[0-9][0-9.a-z_\\\\-]+"))
	data = fixRepeats.ReplaceAll(data, []byte("{0,1000}"))

	err := json.Unmarshal(data, &repos)

	if err != nil {
		fmt.Println("invalid json")
		panic(err)
	}

	libraries := make([]Library, 0)
	for name, library := range repos {
		library.ExtractorRegexps = map[string][]*regexp.Regexp{}
		library.ExtractorRegexps["uri"] = extractorRegexes(library.Extractors.Uri)
		library.ExtractorRegexps["filename"] = extractorRegexes(library.Extractors.Filename)
		library.ExtractorRegexps["filecontent"] = extractorRegexes(library.Extractors.Filecontent)
		library.Name = name
		libraries = append(libraries, library)
	}
	return libraries	
}

func GetRepository() Repository {
	// http://blog.ralch.com/tutorial/design-patterns/golang-singleton/
	once.Do(func() {
		repository = ReadLibraries()
	})
	
	return repository
}

func EvaluateFinding(finding LibraryFinding) ([]VulnerabilityMatch) {
	matches := []VulnerabilityMatch{}

	for _, vuln := range finding.Library.Vulnerabilities {
		above := vuln.AtOrAbove

		if vuln.AtOrAbove == "" {
			above = "0.0"
		}

		comparator := fmt.Sprintf(">=%v,<%v", above, vuln.Below)
		compare := version.NewConstrainGroupFromString(comparator)

		if compare.Match(finding.Version) {
			matches = append(matches, CreateMatch(finding, vuln))
		}
	}

	sort.Sort(byLibrary(matches))

	return matches
}

func EvaluateFindings(findings []LibraryFinding) []VulnerabilityMatch {
	vulns := make([]VulnerabilityMatch, 0)

	for _, finding := range findings {
		matches := EvaluateFinding(finding)

		for _, match := range matches {
			vulns = append(vulns, match)
		}
	}

	return vulns
}

func mapFindings(f []LibraryFinding, m func(LibraryFinding) LibraryFinding) []LibraryFinding {
    all := make([]LibraryFinding, len(f))
    for i, v := range f {
        all[i] = m(v)
    }
    return all
}


func CheckJavascript(repo Repository, url string) []LibraryFinding {
	found := repo.CheckUri([]byte(url))
	if len(found) == 0 {
		base := path.Base(url)
		base = strings.Split(base, "?")[0]
		base = strings.Replace(base, ".min", "", -1)
		found = repo.CheckFilename([]byte(base))
	}
	
	if len(found) == 0 {
		contents := getContent(url)
		hasher := sha1.New()
		hasher.Write(contents)
		sha1d := hasher.Sum(nil)
		hash := hex.EncodeToString(sha1d)
		fmt.Sprintf("%v:%v", hash, url)
		// @todo create cache dir to save time on lookups
		found = repo.CheckContent(contents)
	}

	found = mapFindings(found, func (f LibraryFinding) LibraryFinding {
		f.Asset = url
		return f
	})

	return found
}

func IsLibraryVulnerable(library, version string) bool {
	repo := GetRepository()
	return repo.IsLibraryVulnerable(library, version)
}

func FindScripts(target string) []string{
	if !FileExists(target) {
		return []string{}
	}

	// @todo if is file ...
	scripts := []string{}
	ignoreFolders := []string{".git", ".cache", "node_modules"}
	err := filepath.Walk(target,
	    func(path string, info os.FileInfo, err error) error {
	    if err != nil {
	        return err
	    }

	    if !info.IsDir() && strings.HasSuffix(info.Name(), ".js") {
	    	scripts = append(scripts, path)
	    }

	    // Ignore dot directories
	    if info.IsDir() && strings.HasPrefix(info.Name(), ".") {
        	return filepath.SkipDir
	    }

	    for _, dirname := range ignoreFolders {
		    if info.IsDir() && info.Name() == dirname {
    	    	return filepath.SkipDir
	    	}
	    }

	    return nil
	})
	if err != nil {
	    log.Println(err)
	}

	return scripts
}


func ExtractScripts(target string) []string {
	base, err := url.Parse(target)

	urls := []string{}
	res := fetchUrl(target)
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		fmt.Println(err)
	}

	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if !exists {
			return
		}

		if strings.Contains(src, ".js") {
			if !strings.Contains(src, "://") {
				parsed, err := url.Parse(src)

				if err != nil {
					panic(err)
				}
				urls = append(urls, base.ResolveReference(parsed).String())
			} else {
				urls = append(urls, src)
			}
		}
	})
	return urls
}
