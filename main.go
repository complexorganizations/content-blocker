package main

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/openrdap/rdap"
	"golang.org/x/net/publicsuffix"
)

var (
	advertisementConfig     = "configs/advertisement"
	maliciousConfig         = "configs/malicious"
	socialEngineeringConfig = "configs/social-engineering"
	localExclusion          = "configs/exclusion"
	exclusionDomains        []string
	err                     error
	wg                      sync.WaitGroup
	validation              bool
)

func init() {
	// If any user input flags are provided, use them.
	if len(os.Args) > 1 {
		tempValidation := flag.Bool("validation", false, "Choose whether or not to do domain validation.")
		flag.Parse()
		validation = *tempValidation
	} else {
		validation = false
	}
	// It is impossible for an flag to be both true and false at the same time.
	if validation && !validation {
		log.Fatal("Warning: Validation and no validation cannot be done at the same time.")
	}
	// Remove the old files from your system if they are found.
	os.Remove(advertisementConfig)
	os.Remove(maliciousConfig)
	os.Remove(socialEngineeringConfig)
	// Read through all of the exclusion domains before appending them.
	if fileExists(localExclusion) {
		exclusionDomains = readAndAppend(localExclusion, exclusionDomains)
	}
}

func main() {
	// Scrape all of the domains and save them afterwards.
	startScraping()
	// We'll make everything distinctive once everything is finished.
	makeEverythingUnique(advertisementConfig)
	makeEverythingUnique(maliciousConfig)
	makeEverythingUnique(socialEngineeringConfig)
}

// Replace the URLs in this section to create your own list or add new lists.
func startScraping() {
	// Advertisement
	advertisement := []string{
		"https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
		"https://raw.githubusercontent.com/DRSDavidSoft/additional-hosts/master/domains/blacklist/adservers-and-trackers.txt",
		"https://raw.githubusercontent.com/Ewpratten/youtube_ad_blocklist/master/blocklist.txt",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-Samsung-Adblock-Extension/hosts",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-Spotify-AdBlock-Extension/hosts",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-YouTube-Adblock-Extension/hosts",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-Xiaomi-Extension/hosts",
		"https://raw.githubusercontent.com/HorusTeknoloji/TR-PhishingList/master/url-lists.txt",
		"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
		"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt",
		"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
		"https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
		"https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt",
		"https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/cameleon_at_sysctl.org/master/domains.list",
		"https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts",
		"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
		"https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt",
		"https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
		"https://raw.githubusercontent.com/cbuijs/shallalist/master/adv/domains",
		"https://raw.githubusercontent.com/cbuijs/shallalist/master/tracker/domains",
		"https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
		"https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
		"https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds-Ultra.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/adguarddns-justdomains.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easylist-justdomains.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easyprivacy-justdomains.txt",
		"https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/youtubelist.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/tracking-aggressive-extended.txt",
		"https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt",
		"https://raw.githubusercontent.com/notracking/hosts-blocklists/master/unbound/unbound.blacklist.conf",
		"https://raw.githubusercontent.com/ookangzheng/dbl-oisd-nl/master/dbl.txt",
		"https://raw.githubusercontent.com/tiuxo/hosts/master/ads",
		"https://raw.githubusercontent.com/yous/YousList/master/hosts.txt",
		"https://hblock.molinero.dev/hosts_domains.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt",
		"https://raw.githubusercontent.com/259095/someonewhocares/main/list",
		"https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/domains.txt",
		"https://block.energized.pro/extensions/xtreme/formats/domains.txt",
	}
	// Malicious
	malicious := []string{
		"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/CoinBlockerList/hosts",
		"https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/nocoin-justdomains.txt",
		"https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Regular%20Hosts.txt",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/fakenews/hosts",
		"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
		"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/hate-and-junk-extended.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/crypto.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/drugs.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/smart-tv.txt",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
		"https://badmojr.github.io/1Hosts/Pro/domains.txt",
	}
	// Social Engineering
	socialEngineering := []string{
		"https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/hosts.txt",
		"https://raw.githubusercontent.com/tg12/pihole-phishtank-list/master/list/phish_domains.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/abuse.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
	}
	// Let's start by making everything one-of-a-kind so we don't scrape the same thing twice.
	uniqueAdvertisement := makeUnique(advertisement)
	advertisement = nil
	uniqueMalicious := makeUnique(malicious)
	malicious = nil
	uniqueSocialEngineering := makeUnique(socialEngineering)
	socialEngineering = nil
	// Advertisement
	for i := 0; i < len(uniqueAdvertisement); i++ {
		if validURL(uniqueAdvertisement[i]) {
			saveTheDomains(uniqueAdvertisement[i], advertisementConfig)
		}
	}
	// Malicious
	for i := 0; i < len(uniqueMalicious); i++ {
		if validURL(uniqueMalicious[i]) {
			saveTheDomains(uniqueMalicious[i], maliciousConfig)
		}
	}
	// Social Engineering
	for i := 0; i < len(uniqueSocialEngineering); i++ {
		if validURL(uniqueSocialEngineering[i]) {
			saveTheDomains(uniqueSocialEngineering[i], socialEngineeringConfig)
		}
	}
	wg.Wait()
}

func saveTheDomains(url string, saveLocation string) {
	// Send a request to acquire all the information you need.
	response, err := http.Get(url)
	if err != nil {
		log.Println(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
	}
	// Examine the page's response code.
	if response.StatusCode == 404 {
		log.Println("Sorry, but we were unable to scrape the page you requested due to a 404 error.", url)
	}
	// Scraped data is read and appended to an array.
	var returnContent []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		returnContent = append(returnContent, scanner.Text())
	}
	for a := 0; a < len(returnContent); a++ {
		// If the string begins with a "!", inform the user that it is most likely a browser-level ad block list rather than a domain-level ad block list.
		if strings.HasPrefix(string([]byte(returnContent[a])), "!") {
			log.Println("Error: Most likely, this is a browser-level block list rather than a DNS-level block list.", url)
		}
		// Check to see if the string includes a # prefix, and if it does, skip it.
		if !strings.HasPrefix(string([]byte(returnContent[a])), "#") {
			// Make sure the domain is at least 3 characters long
			if len(string([]byte(returnContent[a]))) > 3 {
				// To find the domains on a page use regex.
				foundDomains := regexp.MustCompile(`(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`).Find([]byte(returnContent[a]))
				if len(string([]byte(foundDomains))) > 3 {
					// Validate the entire list of domains.
					if len(string([]byte(foundDomains))) < 255 && checkIPAddress(string([]byte(foundDomains))) && !strings.Contains(string([]byte(foundDomains)), " ") && strings.Contains(string([]byte(foundDomains)), ".") && !strings.Contains(string([]byte(foundDomains)), "#") && !strings.Contains(string([]byte(foundDomains)), "*") && !strings.Contains(string([]byte(foundDomains)), "!") {
						// icann.org confirms it's a public suffix domain
						eTLD, icann := publicsuffix.PublicSuffix(string([]byte(foundDomains)))
						// Start the other tests if the domain has a valid suffix.
						if icann || strings.IndexByte(eTLD, '.') >= 0 {
							wg.Add(1)
							// Go ahead and verify it in the background.
							go makeDomainsUnique(string([]byte(foundDomains)), saveLocation)
						} else {
							log.Println("Invalid domain suffix:", string([]byte(foundDomains)), url)
						}
					} else {
						log.Println("Invalid domain syntax:", string([]byte(foundDomains)), url)
					}
				}
			}
		}
		// When you're finished, close the body.
		defer response.Body.Close()
		// While the validation is being performed, we wait.
		wg.Wait()
	}
	returnContent = nil
}

func makeDomainsUnique(uniqueDomains string, locatioToSave string) {
	if validation {
		// Validate each and every found domain.
		if validateDomainViaLookupNS(uniqueDomains) || validateDomainViaLookupAddr(uniqueDomains) || validateDomainViaLookupCNAME(uniqueDomains) || validateDomainViaLookupMX(uniqueDomains) || validateDomainViaLookupTXT(uniqueDomains) || validateDomainViaLookupHost(uniqueDomains) || domainRegistration(uniqueDomains) {
			// Maintain a list of all authorized domains.
			writeToFile(locatioToSave, uniqueDomains)
		} else {
			// Let the users know if there are any issues while verifying the domain.
			log.Println("Error validating domain:", uniqueDomains)
		}
	} else {
		// To the list, add all of the domains.
		writeToFile(locatioToSave, uniqueDomains)
	}
	// When it's finished, we'll be able to inform waitgroup that it's finished.
	wg.Done()
}

// Take a list of domains and make them one-of-a-kind
func makeUnique(randomStrings []string) []string {
	flag := make(map[string]bool)
	var uniqueString []string
	for i := 0; i < len(randomStrings); i++ {
		if !flag[randomStrings[i]] {
			flag[randomStrings[i]] = true
			uniqueString = append(uniqueString, randomStrings[i])
		}
	}
	return uniqueString
}

// Using name servers, verify the domain.
func validateDomainViaLookupNS(domain string) bool {
	valid, _ := net.LookupNS(domain)
	return len(valid) >= 1
}

// Using a lookup address, verify the domain.
func validateDomainViaLookupAddr(domain string) bool {
	valid, _ := net.LookupAddr(domain)
	return len(valid) >= 1
}

// Using cname, verify the domain.
func validateDomainViaLookupCNAME(domain string) bool {
	valid, _ := net.LookupCNAME(domain)
	return len(valid) >= 1
}

// mx records are used to validate the domain.
func validateDomainViaLookupMX(domain string) bool {
	valid, _ := net.LookupMX(domain)
	return len(valid) >= 1
}

// Using txt records, validate the domain.
func validateDomainViaLookupTXT(domain string) bool {
	valid, _ := net.LookupTXT(domain)
	return len(valid) >= 1
}

// Using host, see if the domain is legitimate.
func validateDomainViaLookupHost(domain string) bool {
	valid, _ := net.LookupHost(domain)
	return len(valid) >= 1
}

// Validate the domain by checking the domain registration.
func domainRegistration(domain string) bool {
	client := &rdap.Client{}
	_, ok := client.QueryDomain(domain)
	return ok == nil
}

// Make sure it's not an IP address.
func checkIPAddress(ip string) bool {
	return net.ParseIP(ip) == nil
}

// Verify the URI.
func validURL(uri string) bool {
	_, err = url.ParseRequestURI(uri)
	return err == nil
}

// Check to see if a file already exists.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// Remove a string from a slice
func removeStringFromSlice(originalSlice []string, removeString string) []string {
	for i := 0; i < len(originalSlice); i++ {
		if originalSlice[i] == removeString {
			return append(originalSlice[:i], originalSlice[i+1:]...)
		}
	}
	return originalSlice
}

// Save the information to a file.
func writeToFile(pathInSystem string, content string) {
	filePath, err := os.OpenFile(pathInSystem, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	_, err = filePath.WriteString(content + "\n")
	if err != nil {
		log.Println(err)
	}
	defer filePath.Close()
}

// Read and append to array
func readAndAppend(fileLocation string, arrayName []string) []string {
	file, err := os.Open(fileLocation)
	if err != nil {
		log.Println(err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		arrayName = append(arrayName, scanner.Text())
	}
	defer file.Close()
	return arrayName
}

// Read the completed file, then delete any duplicates before saving it.
func makeEverythingUnique(contentLocation string) {
	var finalDomainList []string
	finalDomainList = readAndAppend(contentLocation, finalDomainList)
	// Make each domain one-of-a-kind.
	uniqueDomains := makeUnique(finalDomainList)
	// It is recommended that the array be deleted from memory.
	finalDomainList = nil
	// Sort the entire string.
	sort.Strings(uniqueDomains)
	// Remove all the exclusions domains from the list.
	for a := 0; a < len(exclusionDomains); a++ {
		uniqueDomains = removeStringFromSlice(uniqueDomains, exclusionDomains[a])
	}
	// Delete the original file and rewrite it.
	err = os.Remove(contentLocation)
	if err != nil {
		log.Println(err)
	}
	// Begin composing the document
	for i := 0; i < len(uniqueDomains); i++ {
		writeToFile(contentLocation, uniqueDomains[i])
	}
	uniqueDomains = nil
}
