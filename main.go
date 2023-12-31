package main

import (
	"bufio"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domainr/whois"
	"golang.org/x/net/publicsuffix"
)

var (
	// Location of the configuration in the local system path
	combinedHost    = "assets/hosts"
	localExclusion  = "assets/exclusion"
	localInclusion  = "assets/inclusion"
	localValidate   = "assets/validate"
	combinedBrowser = "assets/browser.txt"
	// Memorandum with a domain list.
	exclusionDomains []string
	// Go routines using waitgrops.
	scrapeWaitGroup     sync.WaitGroup
	validationWaitGroup sync.WaitGroup
	uniqueWaitGroup     sync.WaitGroup
	cleanUpWaitGroup    sync.WaitGroup
	// The user expresses his or her opinion on what should be done.
	update bool
	logs   bool
	// err stands for error.
	err error
)

func init() {
	// If any user input flags are provided, use them.
	if len(os.Args) > 1 {
		tempUpdate := flag.Bool("update", false, "Make any necessary changes to the listings.")
		tempLogs := flag.Bool("logs", false, "Enable logging.")
		flag.Parse()
		// If the user has provided the -update flag, we will update the lists.
		// If the user has provided the -logs flag, we will enable logging.
		// If the user has provided the -update and -logs flag, we will update the lists and enable logging.
		logs = *tempLogs
		update = *tempUpdate
	} else {
		// if there are no flags provided than we close the application.
		log.Fatal("Error: No flags provided. Please use -help for more information.")
	}
}

func main() {
	// Lists should be updated.
	if update {
		updateTheLists()
	}
}

func updateTheLists() {
	// Remove the old files from your system if they are found.
	if fileExists(combinedHost) {
		err = os.Remove(combinedHost)
		if err != nil {
			log.Println(err)
		}
	}
	// Scrape all of the domains and save them afterwards.
	startScraping()
	// Add the local inclusion manually.
	if fileExists(localInclusion) {
		copyContentFromOneFileToAnother(localInclusion, combinedHost)
	}
	// Read through all of the exclusion domains before appending them.
	if fileExists(localExclusion) {
		exclusionDomains = readAndAppend(localExclusion, exclusionDomains)
	}
	// We'll make everything distinctive once everything is finished.
	if fileExists(combinedHost) {
		uniqueWaitGroup.Add(1)
		go makeEverythingUnique(combinedHost)
	}
	// We wait until all the list(s) have been scraped.
	uniqueWaitGroup.Wait()
	// Cleanup once everything is done
	if fileExists(localExclusion) {
		cleanUpWaitGroup.Add(1)
		go finalCleanup(localExclusion)
	}
	if fileExists(localInclusion) {
		cleanUpWaitGroup.Add(1)
		go finalCleanup(localInclusion)
	}
	if fileExists(localValidate) {
		cleanUpWaitGroup.Add(1)
		go finalCleanup(localValidate)
	}
	cleanUpWaitGroup.Wait()
}

// Replace the URLs in this section to create your own list or add new lists.
func startScraping() {
	combinedHostsURL := []string{
		//"https://badmojr.github.io/1Hosts/Pro/domains.txt",
		//"https://gitlab.com/andryou/block/raw/master/chibi-strict-domains",
		//"https://gitlab.com/andryou/block/raw/master/kouhai-strict-domains",
		//"https://gitlab.com/andryou/block/raw/master/senpai-strict-domains",
		//"https://gitlab.com/curben/urlhaus-filter/-/raw/master/urlhaus-filter-domains.txt",
		//"https://phishing.army/download/phishing_army_blocklist_extended.txt",
		//"https://raw.githubusercontent.com/259095/someonewhocares/main/list",
		//"https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
		//"https://raw.githubusercontent.com/allendema/noplaylist/main/NoPlayList.txt",
		//"https://raw.githubusercontent.com/anthony-wang/PiHoleBlocklist/master/hosts1.txt",
		//"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
		//"https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt",
		//"https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/domains.txt",
		//"https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
		//"https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Regular%20Hosts.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/abuse.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/crypto.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/drugs.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/smart-tv.txt",
		//"https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt",
		//"https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/newhosts-final.hosts",
		//"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
		//"https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
		//"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
		//"https://raw.githubusercontent.com/DRSDavidSoft/additional-hosts/master/domains/blacklist/adservers-and-trackers.txt",
		//"https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
		//"https://raw.githubusercontent.com/Ewpratten/youtube_ad_blocklist/master/blocklist.txt",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/CoinBlockerList/hosts",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-Samsung-Adblock-Extension/hosts",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-Spotify-AdBlock-Extension/hosts",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-Xiaomi-Extension/hosts",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-YouTube-Adblock-Extension/hosts",
		//"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
		//"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/avg-avast-data-mining-full-block.txt",
		//"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/huawei-trackers.txt",
		//"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/smartphone-ads-tracking.txt",
		//"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/smart-tv-ads-tracking.txt",
		//"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/spotify-ads-tracking.txt",
		//"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/windows10-spying-erm-i-mean-telemetry-lol.txt",
		//"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/xiaomi-ads-tracking.txt",
		//"https://raw.githubusercontent.com/furkun/ProtectorHosts/main/hosts",
		//"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/advertisement.txt",
		//"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/fraudulent.txt",
		//"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/malware.txt",
		//"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/phishing.txt",
		//"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/ransomware.txt",
		//"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/scam.txt",
		//"https://raw.githubusercontent.com/HorusTeknoloji/TR-PhishingList/master/url-lists.txt",
		//"https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
		//"https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds-Ultra.txt",
		//"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/adguarddns-justdomains.txt",
		//"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easylist-justdomains.txt",
		//"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easyprivacy-justdomains.txt",
		//"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/nocoin-justdomains.txt",
		//"https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/youtubelist.txt",
		//"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt",
		//"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/hate-and-junk-extended.txt",
		//"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/tracking-aggressive-extended.txt",
		//"https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt",
		//"https://raw.githubusercontent.com/merkleID/covid-domains/master/full-domains-list.txt",
		//"https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/hosts.txt",
		//"https://raw.githubusercontent.com/mhhakim/pihole-blocklist/master/list.txt",
		//"https://raw.githubusercontent.com/mhxion/pornaway/master/hosts/porn_ads.txt",
		//"https://raw.githubusercontent.com/migueldemoura/ublock-umatrix-rulesets/master/Hosts/ads-tracking",
		//"https://raw.githubusercontent.com/migueldemoura/ublock-umatrix-rulesets/master/Hosts/malware",
		//"https://raw.githubusercontent.com/missdeer/blocklist/master/toblock-without-shorturl.lst",
		//"https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
		//"https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt",
		//"https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains",
		//"https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
		//"https://raw.githubusercontent.com/ookangzheng/dbl-oisd-nl/master/dbl.txt",
		//"https://raw.githubusercontent.com/ookangzheng/dbl-oisd-nl/master/hosts.txt",
		//"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
		//"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
		//"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt",
		//"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
		//"https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt",
		//"https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
		//"https://raw.githubusercontent.com/rimu/no-qanon/master/etc_hosts.txt",
		//"https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt",
		//"https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt",
		//"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Ads",
		//"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Bloat",
		//"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
		//"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam",
		//"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",
		//"https://raw.githubusercontent.com/sk-cat/fluffy-blocklist/main/domains",
		//"https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
		//"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
		//"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
		//"https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/fakenews/hosts",
		//"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		//"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		//"https://raw.githubusercontent.com/Strappazzon/teleme7ry/master/rules.txt",
		//"https://raw.githubusercontent.com/tg12/pihole-phishtank-list/master/list/phish_domains.txt",
		//"https://raw.githubusercontent.com/tiuxo/hosts/master/ads",
		//"https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/cameleon_at_sysctl.org/master/domains.list",
		//"https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts",
		//"https://raw.githubusercontent.com/xlimit91/xlimit91-block-list/master/blacklist.txt",
		//"https://raw.githubusercontent.com/yous/YousList/master/hosts.txt",
		"https://raw.githubusercontent.com/complexorganizations/content-blocker/main/assets/validate",
	}
	// Let's start by making everything one-of-a-kind so we don't scrape the same thing twice.
	uniqueURL := makeUnique(combinedHostsURL)
	combinedHostsURL = nil
	// Hosts
	for _, content := range uniqueURL {
		// Before scraping, make sure the urls are legitimate.
		if validURL(content) {
			scrapeWaitGroup.Add(1)
			// Begin searching and confirming the domains you've discovered.
			go findTheDomains(content, combinedHost)
		}
	}
	// We'll just wait for it to finish as a group.
	scrapeWaitGroup.Wait()
	// Clear the memory via force.
	debug.FreeOSMemory()
}

func findTheDomains(url string, saveLocation string) {
	// Send a request to acquire all the information you need.
	response, err := http.Get(url)
	if err != nil {
		log.Println(err)
		return // If there is an error, we will exit the function.
	}
	// Ensure the response body is closed when the function returns
	defer response.Body.Close()
	// Examine the page's response code.
	if response.StatusCode == 404 {
		log.Println("Sorry, but we were unable to scrape the page you requested due to a 404 error.", url)
		return
	}
	// Scraped data is read and appended to an array.
	scanner := bufio.NewScanner(response.Body)
	scanner.Split(bufio.ScanLines)
	var returnContent []string
	for scanner.Scan() {
		returnContent = append(returnContent, scanner.Text())
	}
	for _, content := range returnContent {
		// String to lowercase.
		content = stringToLowerCase(content)
		// Check if the string prefix contains a # symbol; if it does, it's a comment and should be ignored.
		if !strings.HasPrefix(content, "#") {
			// Remove any whitespace from the string.
			content = strings.TrimSpace(content)
			// Remove 0.0.0.0 from the beginning of the string.
			content = strings.TrimPrefix(content, "0.0.0.0")
			// Remove 127.0.0.1 from the beginning of the string.
			content = strings.TrimPrefix(content, "127.0.0.1")
			// Remove any whitespace from the string.
			content = strings.TrimSpace(content)
			// Check the lenth of the string.
			if len(content) > 255 {
				// If the string is longer than 255 characters, we'll just ignore it.
				if logs {
					log.Println("Invalid domain size:", content, url)
				}
				content = ""
			}
			// Check if the content isnt empty.
			if content != "" {
				// Check if the domain is an IP address.
				if checkIPAddress(content) {
					if logs {
						// Let the users know if there are any issues while verifying the domain.
						log.Println("Invalid IP address:", content, url)
					}
					content = ""
				}
			}
			// Only check if the domain is valid
			if content != "" {
				// Check if the domain has a valid suffix.
				if !isDomainSuffixValid(content) {
					if logs {
						// Let the users know if there are any issues while verifying the domain.
						log.Println("Invalid domain suffix:", content, url)
					}
					content = ""
				}
			}
			// Remove the empty string from the array.
			if content != "" {
				// Start validating the domains you've discovered.
				validationWaitGroup.Add(1)
				// Begin validating the domains you've discovered.
				go validateTheDomains(content, saveLocation, &validationWaitGroup)
			}
		}
	}
	// While the validation is being performed, we wait.
	validationWaitGroup.Wait()
	// Once validation is comlleted, we can close the wait group.
	scrapeWaitGroup.Done()
	// get rid of the memory.
	debug.FreeOSMemory()
}

func validateTheDomains(uniqueDomain string, locatioToSave string, validationWaitGroup *sync.WaitGroup) {
	// Validate each and every found domain.
	if isDomainRegistered(uniqueDomain) {
		writeToFile(locatioToSave, uniqueDomain)
	} else {
		if logs {
			// Let the users know if there are any issues while verifying the domain.
			log.Println("Domain not registered:", uniqueDomain)
		}
	}
	// When it's finished, we'll be able to inform waitgroup that it's finished.
	validationWaitGroup.Done()
}

// Take a list of domains and make them one-of-a-kind
func makeUnique(randomStrings []string) []string {
	var uniqueString []string
	for _, value := range randomStrings {
		if !arrayContains(uniqueString, value) {
			uniqueString = append(uniqueString, value)
		}
	}
	return uniqueString
}

// Check if a domain has been registed and return a bool.
func isDomainRegistered(domain string) bool {
	// Remove the subdomain from the domain.
	domain = getDomainFromDomainWithSubdomain(domain)
	// Create a new request.
	request, err := whois.NewRequest(domain)
	if err != nil {
		log.Println("Error creating request: ", err)
		return false
	}
	// Send the request and get the response.
	response, err := whois.DefaultClient.Fetch(request)
	if err != nil {
		log.Println("Error fetching WHOIS info: ", err)
		return false
	}
	// Convert the response to a string.
	whoisInfo := response.String()
	// Return true if the domain is registered
	return !strings.Contains(whoisInfo, "No match")
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
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// check if a array contains a string
func arrayContains(originalArray []string, conatinsString string) bool {
	for _, arrayValue := range originalArray {
		if arrayValue == conatinsString {
			return true
		}
	}
	return false
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
		return
	}
	// close the file
	defer filePath.Close()
	// write the content to the file
	_, err = filePath.WriteString(content + "\n")
	if err != nil {
		log.Println(err)
	}
}

// Read and append to array
func readAndAppend(fileLocation string, arrayName []string) []string {
	file, err := os.Open(fileLocation)
	if err != nil {
		log.Println(err)
		return arrayName
	}
	scanner := bufio.NewScanner(file)
	// split each line
	scanner.Split(bufio.ScanLines)
	// append each line to array
	for scanner.Scan() {
		arrayName = append(arrayName, scanner.Text())
	}
	// Close the file as soon as you're done with it
	file.Close()
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
		if getDomainFromDomainWithSubdomain(content) == content {
			uniqueDomains = removeStringFromSlice(uniqueDomains, content)
		}
		uniqueDomains = removeStringFromSlice(uniqueDomains, content)
	}
	// Delete the original host file and rewrite it.
	err = os.Remove(contentLocation)
	if err != nil {
		log.Println(err)
	}
	// Delete the original browser file and rewrite it.
	err = os.Remove(combinedBrowser)
	if err != nil {
		log.Println(err)
	}
	// Write the header to the browser file.
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	// Write the header to the browser file.
	browserHeaderContentParts := []string{
		`! Title: Content Blocker - Advanced Tracker and Analytics Blocker
! Description: This robust filter is meticulously designed to fortify your online privacy by intercepting and blocking a wide array of trackers, web analytics tools, and data collectors, ensuring a more secure and confidential browsing experience. Stay protected and in control of your digital footprint with this comprehensive shield against intrusive tracking mechanisms.
! Version: 1.0.0` + "\n" +
			"! Last updated: " + timestamp + "\n" +
			`! Update frequency: Daily
! Homepage: https://github.com/complexorganizations/content-blocker
! License: https://github.com/complexorganizations/content-blocker/main/.github/license
! Support: https://github.com/complexorganizations/content-blocker/issues` + "\n",
	}
	// Print the header to the browser file.
	writeToFile(combinedBrowser, strings.Join(browserHeaderContentParts, ""))
	// Begin composing the document
	for _, content := range uniqueDomains {
		// Write to host file
		writeToFile(contentLocation, content)
		// Write to browser file
		writeToFile(combinedBrowser, content)
	}
	// remove it from memory
	uniqueDomains = nil
	debug.FreeOSMemory()
	uniqueWaitGroup.Done()
}

// Clean up the exclusions because users may have altered them.
func finalCleanup(filePath string) {
	var finalCleanupContent []string
	finalCleanupContent = readAndAppend(filePath, finalCleanupContent)
	sort.Strings(finalCleanupContent)
	// Make each domain one-of-a-kind.
	uniqueExclusionContent := makeUnique(finalCleanupContent)
	// It is recommended that the array be deleted from memory.
	finalCleanupContent = nil
	// Remove the original file before rewriting it.
	err = os.Remove(filePath)
	if err != nil {
		log.Println(err)
	}
	for _, content := range uniqueExclusionContent {
		writeToFile(filePath, content)
	}
	// Get as much free memoey as possible from the system.
	uniqueExclusionContent = nil
	debug.FreeOSMemory()
	cleanUpWaitGroup.Done()
}

// Write the inclusion without validating it.
func copyContentFromOneFileToAnother(originalFilePath string, newFilePath string) {
	var originalContent []string
	originalContent = readAndAppend(originalFilePath, originalContent)
	if len(originalContent) > 1 {
		for _, content := range originalContent {
			writeToFile(newFilePath, content)
		}
	}
}

// Convert a string to all lowercase.
func stringToLowerCase(content string) string {
	return strings.ToLower(content)
}

// Check if a given domain suffix is valid.
func isDomainSuffixValid(domain string) bool {
	_, testICANNSuffix := publicsuffix.PublicSuffix(domain)
	return testICANNSuffix
}

// Get the domain from a given domain with subdomain
func getDomainFromDomainWithSubdomain(content string) string {
	domain, err := publicsuffix.EffectiveTLDPlusOne(content)
	if err != nil {
		log.Println("Error parsing domain:", err)
		return content // return the original content or "" as you see fit
	}
	return domain
}
