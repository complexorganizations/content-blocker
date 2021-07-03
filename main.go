package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"

	"github.com/openrdap/rdap"
	"golang.org/x/net/publicsuffix"
)

var (
	// Location of the configuration in the local system path
	advertisementConfig     = "configs/advertisement"
	maliciousConfig         = "configs/malicious"
	socialEngineeringConfig = "configs/social-engineering"
	localExclusion          = "configs/exclusion"
	explicitConfig          = "configs/explicit"
	// Memorandum with a domain list.
	exclusionDomains       []string
	advertisementArray     []string
	maliciousArray         []string
	socialEngineeringArray []string
	exclusionArray         []string
	// Go routines using waitgrops.
	scrapeWaitGroup     sync.WaitGroup
	validationWaitGroup sync.WaitGroup
	uniqueWaitGroup sync.WaitGroup
	// The user expresses his or her opinion on what should be done.
	showLogs  bool
	update    bool
	install   bool
	uninstall bool
	// err stands for error.
	err error
)

func init() {
	// If any user input flags are provided, use them.
	if len(os.Args) > 1 {
		tempUpdate := flag.Bool("update", false, "Make any necessary changes to the listings.")
		tempLog := flag.Bool("logs", false, "Check the weather before deciding whether or not to display logs.")
		tempInstall := flag.Bool("install", false, "Install the list into your operating system.")
		tempUninstall := flag.Bool("uninstall", false, "Uninstall the list from your operating system.")
		flag.Parse()
		update = *tempUpdate
		showLogs = *tempLog
		install = *tempInstall
		uninstall = *tempUninstall
	} else {
		os.Exit(0)
	}
}

func main() {
	// In your system, place the host file.
	if install {
		installInSystem()
	}
	// Uninstall the host file from your system
	if uninstall {
		uninstallInSystem()
	}
	// Lists should be updated.
	if update {
		// Clear your memories as much as possible
		os.RemoveAll(os.TempDir())
		os.Mkdir(os.TempDir(), 0777)
		debug.FreeOSMemory()
		// Max ammount of go routines
		debug.SetMaxThreads(10000)
		// Remove the old files from your system if they are found.
		err = os.Remove(advertisementConfig)
		if err != nil {
			log.Println(err)
		}
		err = os.Remove(maliciousConfig)
		if err != nil {
			log.Println(err)
		}
		err = os.Remove(socialEngineeringConfig)
		if err != nil {
			log.Println(err)
		}
		err = os.Remove(explicitConfig)
		if err != nil {
			log.Println(err)
		}
		// Read through all of the exclusion domains before appending them.
		if fileExists(localExclusion) {
			exclusionDomains = readAndAppend(localExclusion, exclusionDomains)
		}
		// Scrape all of the domains and save them afterwards.
		startScraping()
		// We'll make everything distinctive once everything is finished.
		uniqueWaitGroup.Add(4)
		go makeEverythingUnique(advertisementConfig)
		go makeEverythingUnique(maliciousConfig)
		go makeEverythingUnique(socialEngineeringConfig)
		go makeEverythingUnique(explicitConfig)
		uniqueWaitGroup.Wait()
	}
}

// Configure your system to use the lists.
func installInSystem() {
	fmt.Println("Which of the following lists would you like to add to your system?")
	fmt.Println("1. Advertisement")
	fmt.Println("2. Malicious")
	fmt.Println("3. Social-Engineering")
	fmt.Println("4. Explicit")
	var userInput int
	fmt.Scanln(&userInput)
	// Set up the lists on your computer.
	advertisement := "https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/advertisement"
	malicious := "https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/malicious"
	socialEngineering := "https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/social-engineering"
	explicit := "https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/explicit"
	// Take user input and check the operating system.
	var systemHostFile string
	switch runtime.GOOS {
	case "windows":
		systemHostFile = `C:\Windows\System32\drivers\etc\hosts`
	case "darwin", "linux":
		systemHostFile = "/etc/hosts"
	}
	// Select the list you want to install in your system.
	switch userInput {
	case 1:
		downloadFile(advertisement, systemHostFile)
	case 2:
		downloadFile(malicious, systemHostFile)
	case 3:
		downloadFile(socialEngineering, systemHostFile)
	case 4:
		downloadFile(explicit, systemHostFile)
	default:
		os.Exit(0)
	}
}

// Remove it from your computer's operating system.
func uninstallInSystem() {
	var systemHostFile string
	switch runtime.GOOS {
	case "windows":
		systemHostFile = `C:\Windows\System32\drivers\etc\hosts`
	case "darwin", "linux":
		systemHostFile = "/etc/hosts"
	}
	err = os.Remove(systemHostFile)
	if err != nil {
		log.Println(err)
	}
}

// Replace the URLs in this section to create your own list or add new lists.
func startScraping() {
	// Advertisement
	advertisement := []string{
		"https://raw.githubusercontent.com/259095/someonewhocares/main/list",
		"https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
		"https://raw.githubusercontent.com/DRSDavidSoft/additional-hosts/master/domains/blacklist/adservers-and-trackers.txt",
		"https://raw.githubusercontent.com/Ewpratten/youtube_ad_blocklist/master/blocklist.txt",
		"https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Ads",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/cameleon_at_sysctl.org/master/domains.list",
		"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
		"https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt",
		"https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/domains.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt",
		"https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/adguarddns-justdomains.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easylist-justdomains.txt",
		"https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
		"https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/youtubelist.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt",
		"https://raw.githubusercontent.com/mhhakim/pihole-blocklist/master/list.txt",
		"https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt",
		"https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
		"https://raw.githubusercontent.com/ookangzheng/dbl-oisd-nl/master/dbl.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/smart-tv.txt",
	}
	// Malicious
	malicious := []string{
		"https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Regular%20Hosts.txt",
		"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareDomains.txt",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Bloat",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
		"https://raw.githubusercontent.com/allendema/noplaylist/main/NoPlayList.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt",
		"https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/newhosts-final.hosts",
		"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
		"https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
		"https://raw.githubusercontent.com/furkun/ProtectorHosts/main/hosts",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easyprivacy-justdomains.txt",
		"https://raw.githubusercontent.com/infinitytec/blocklists/master/scams-and-phishing.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/hate-and-junk-extended.txt",
		"https://raw.githubusercontent.com/matomo-org/referrer-spam-list/master/spammers.txt",
		"https://raw.githubusercontent.com/missdeer/blocklist/master/toblock-without-shorturl.lst",
		"https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
		"https://raw.githubusercontent.com/rimu/no-qanon/master/etc_hosts.txt",
		"https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestdomains.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/tracking-aggressive-extended.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt",
	}
	// Social Engineering
	socialEngineering := []string{
		"https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/hosts.txt",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/abuse.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
		"https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
		"https://raw.githubusercontent.com/tg12/pihole-phishtank-list/master/list/phish_domains.txt",
		"https://block.energized.pro/ultimate/formats/domains.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
		"https://hblock.molinero.dev/hosts_domains.txt",
	}
	// Adult content
	explicit := []string{
		"https://raw.githubusercontent.com/Bon-Appetit/porn-domains/master/block.txt",
		"https://raw.githubusercontent.com/Clefspeare13/pornhosts/master/0.0.0.0/hosts",
		"https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
		"https://raw.githubusercontent.com/mhhakim/pihole-blocklist/master/porn.txt",
		"https://raw.githubusercontent.com/tiuxo/hosts/master/porn",
		"https://block.energized.pro/porn/formats/domains.txt",
	}
	// Let's start by making everything one-of-a-kind so we don't scrape the same thing twice.
	uniqueAdvertisement := makeUnique(advertisement)
	advertisement = nil
	uniqueMalicious := makeUnique(malicious)
	malicious = nil
	uniqueSocialEngineering := makeUnique(socialEngineering)
	socialEngineering = nil
	uniqueExplicit := makeUnique(explicit)
	explicit = nil
	// Advertisement
	for _, content := range uniqueAdvertisement {
		if validURL(content) {
			scrapeWaitGroup.Add(1)
			// Begin searching and confirming the domains you've discovered.
			go findTheDomains(content, advertisementConfig, advertisementArray)
		}
	}
	// Malicious
	for _, content := range uniqueMalicious {
		if validURL(content) {
			scrapeWaitGroup.Add(1)
			// Begin looking for and verifying the domains you've found.
			go findTheDomains(content, maliciousConfig, maliciousArray)
		}
	}
	// Social Engineering
	for _, content := range uniqueSocialEngineering {
		if validURL(content) {
			scrapeWaitGroup.Add(1)
			// Begin searching for and confirming the domains you've discovered.
			go findTheDomains(content, socialEngineeringConfig, socialEngineeringArray)
		}
	}
	// Explicit
	for _, content := range uniqueExplicit {
		if validURL(content) {
			scrapeWaitGroup.Add(1)
			// Begin looking for and verifying the domains you've found.
			go findTheDomains(content, explicitConfig, exclusionArray)
		}
	}
	// Clear the memory via force.
	debug.FreeOSMemory()
	// We'll just wait for it to finish as a group.
	scrapeWaitGroup.Wait()
}

func findTheDomains(url string, saveLocation string, returnContent []string) {
	// Send a request to acquire all the information you need.
	response, err := http.Get(url)
	if err != nil {
		log.Println(err)
	}
	// read all the content of the body.
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
	}
	// Examine the page's response code.
	if response.StatusCode == 404 {
		log.Println("Sorry, but we were unable to scrape the page you requested due to a 404 error.", url)
	}
	// Scraped data is read and appended to an array.
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		returnContent = append(returnContent, scanner.Text())
	}
	// When you're finished, close the body.
	response.Body.Close()
	for _, content := range returnContent {
		// If the string begins with a "!", inform the user that it is most likely a browser-level ad block list rather than a domain-level ad block list.
		if strings.HasPrefix(content, "!") {
			log.Println("Error: Most likely, this is a browser-level block list rather than a DNS-level block list.", url)
		}
		// Check to see if the string includes a # prefix, and if it does, skip it.
		if !strings.HasPrefix(content, "#") {
			// Make sure the domain is at least 3 characters long
			if len(content) > 1 {
				// This is a list of all the domains discovered using the regex.
				foundDomains := regexp.MustCompile(`(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`).Find([]byte(content))
				// all the emails from rejex
				foundDomain := string(foundDomains)
				if len(foundDomain) > 3 {
					// Validate the entire list of domains.
					if len(foundDomain) < 255 && checkIPAddress(foundDomain) && !strings.Contains(foundDomain, " ") && strings.Contains(foundDomain, ".") && !strings.Contains(foundDomain, "#") && !strings.Contains(foundDomain, "*") && !strings.Contains(foundDomain, "!") {
						// icann.org confirms it's a public suffix domain
						eTLD, icann := publicsuffix.PublicSuffix(foundDomain)
						// Start the other tests if the domain has a valid suffix.
						if icann || strings.IndexByte(eTLD, '.') >= 0 {
							validationWaitGroup.Add(1)
							// Go ahead and verify it in the background.
							go validateTheDomains(foundDomain, saveLocation)
						} else {
							// Because we know it's not a legitimate suffix, it informs the user that the domain is invalid.
							if showLogs {
								log.Println("Invalid domain suffix:", foundDomain, url)
							}
						}
					} else {
						// Let the user know that the domain is invalid since it does not fit the syntax.
						if showLogs {
							log.Println("Invalid domain syntax:", foundDomain, url)
						}
					}
				}
			}
		}
	}
	debug.FreeOSMemory()
	scrapeWaitGroup.Done()
	// While the validation is being performed, we wait.
	validationWaitGroup.Wait()
}

func validateTheDomains(uniqueDomain string, locatioToSave string) {
	// Validate each and every found domain.
	if validateDomainViaLookupNS(uniqueDomain) || validateDomainViaLookupAddr(uniqueDomain) || validateDomainViaLookupIP(uniqueDomain) || validateDomainViaLookupCNAME(uniqueDomain) || validateDomainViaLookupMX(uniqueDomain) || validateDomainViaLookupTXT(uniqueDomain) || validateDomainViaLookupHost(uniqueDomain) || domainRegistration(uniqueDomain) || validateDomainViaHTTP(uniqueDomain) || validateDomainViaHTTPS(uniqueDomain) || validateApplicationViaHTTP(uniqueDomain) || validateApplicationViaHTTPS(uniqueDomain) {
		// Maintain a list of all authorized domains.
		writeToFile(locatioToSave, uniqueDomain)
		if showLogs {
			log.Println("Valid domain:", uniqueDomain)
		}
	} else {
		// Let the users know if there are any issues while verifying the domain.
		if showLogs {
			log.Println("Error validating domain:", uniqueDomain)
		}
	}
	// When it's finished, we'll be able to inform waitgroup that it's finished.
	validationWaitGroup.Done()
}

// Take a list of domains and make them one-of-a-kind
func makeUnique(randomStrings []string) []string {
	flag := make(map[string]bool)
	var uniqueString []string
	for _, content := range randomStrings {
		if !flag[content] {
			flag[content] = true
			uniqueString = append(uniqueString, content)
		}
	}
	return uniqueString
}

// Using name servers, verify the domain.
func validateDomainViaLookupNS(domain string) bool {
	valid, _ := net.LookupNS(domain)
	return len(valid) >= 1
}

// Using ip address, verify the domain.
func validateDomainViaLookupIP(domain string) bool {
	valid, _ := net.LookupIP(domain)
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

// Ping the server using http to see if anything is there.
func validateDomainViaHTTP(domain string) bool {
	pingThis := fmt.Sprint(domain + ":" + "80")
	_, err := net.Dial("tcp", pingThis)
	return err == nil
}

// Using https, ping the server and see if anything is there.
func validateDomainViaHTTPS(domain string) bool {
	pingThis := fmt.Sprint(domain + ":" + "443")
	_, err := net.Dial("tcp", pingThis)
	return err == nil
}

// To check if the website is up and functioning, send an HTTP request to it.
func validateApplicationViaHTTP(domain string) bool {
	httpValue := fmt.Sprint("http://" + domain)
	_, err := http.Get(httpValue)
	return err == nil
}

// Send a request to see if the program is running.
func validateApplicationViaHTTPS(domain string) bool {
	httpValue := fmt.Sprint("https://" + domain)
	_, err := http.Get(httpValue)
	return err == nil
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
	// go though the array
	for i, content := range originalSlice {
		// if the array matches with the string, you remove it from the array
		if content == removeString {
			return append(originalSlice[:i], originalSlice[i+1:]...)
		}
	}
	return originalSlice
}

// Save the information to a file.
func writeToFile(pathInSystem string, content string) {
	// open the file and if its not there create one.
	filePath, err := os.OpenFile(pathInSystem, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	// write the content to the file
	_, err = filePath.WriteString(content + "\n")
	if err != nil {
		log.Println(err)
	}
	// close the file
	defer filePath.Close()
}

// Read and append to array
func readAndAppend(fileLocation string, arrayName []string) []string {
	file, err := os.Open(fileLocation)
	if err != nil {
		log.Println(err)
	}
	// scan the file, and read the file
	scanner := bufio.NewScanner(file)
	// split each line
	scanner.Split(bufio.ScanLines)
	// append each line to array
	for scanner.Scan() {
		arrayName = append(arrayName, scanner.Text())
	}
	// close the file before func ends
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
	for _, content := range exclusionDomains {
		uniqueDomains = removeStringFromSlice(uniqueDomains, content)
	}
	// Delete the original file and rewrite it.
	err = os.Remove(contentLocation)
	if err != nil {
		log.Println(err)
	}
	// Begin composing the document
	for _, content := range uniqueDomains {
		writeToFile(contentLocation, content)
	}
	// remove it from memory
	uniqueDomains = nil
	debug.FreeOSMemory()
}

// Download a file in your system
func downloadFile(url string, filePath string) {
	// Send a request to acquire all the information you need.
	response, err := http.Get(url)
	if err != nil {
		log.Println(err)
	}
	// read all the content of the body.
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
	}
	// Scraped data is read and appended to an array.
	var returnContent []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		returnContent = append(returnContent, scanner.Text())
	}
	// Remove the original file before rewriting it.
	err = os.Remove(filePath)
	if err != nil {
		log.Println(err)
	}
	for _, content := range returnContent {
		contentToWrite := fmt.Sprintln("0.0.0.0", content)
		writeToFile(filePath, contentToWrite)
	}
	uniqueWaitGroup.Done()
	// Get as much free memoey as possible from the system.
	returnContent = nil
	debug.FreeOSMemory()
}
