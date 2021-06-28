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
	allInOneBlockList       = "configs/hosts"
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
	// The user expresses his or her opinion on what should be done.
	validation  bool
	showLogs    bool
	update      bool
	install     bool
	uninstall   bool
	performance bool
	// err stands for error.
	err error
)

func init() {
	// If any user input flags are provided, use them.
	if len(os.Args) > 1 {
		tempValidation := flag.Bool("validation", false, "Choose whether or not to do domain validation.")
		tempLog := flag.Bool("logs", false, "Check the weather before deciding whether or not to display logs.")
		tempUpdate := flag.Bool("update", false, "Make any necessary changes to the listings.")
		tempInstall := flag.Bool("install", false, "Install the list into your operating system.")
		tempUninstall := flag.Bool("uninstall", false, "Uninstall the list from your operating system.")
		tempPerformance := flag.Bool("performance", false, "Don't put too much strain on the system.")
		flag.Parse()
		validation = *tempValidation
		showLogs = *tempLog
		update = *tempUpdate
		install = *tempInstall
		uninstall = *tempUninstall
		performance = *tempPerformance
	} else {
		os.Exit(0)
	}
	// To free up some memory, delete all of the files in temp.
	os.RemoveAll(os.TempDir())
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
		// Remove the old files from your system if they are found.
		os.Remove(allInOneBlockList)
		os.Remove(advertisementConfig)
		os.Remove(maliciousConfig)
		os.Remove(socialEngineeringConfig)
		os.Remove(explicitConfig)
		// Read through all of the exclusion domains before appending them.
		if fileExists(localExclusion) {
			exclusionDomains = readAndAppend(localExclusion, exclusionDomains)
		}
		// Scrape all of the domains and save them afterwards.
		startScraping()
		// We'll make everything distinctive once everything is finished.
		makeEverythingUnique(allInOneBlockList)
		makeEverythingUnique(advertisementConfig)
		makeEverythingUnique(maliciousConfig)
		makeEverythingUnique(socialEngineeringConfig)
		makeEverythingUnique(explicitConfig)
	}
}

// Configure your system to use the lists.
func installInSystem() {
	fmt.Println("Which of the following lists would you like to add to your system?")
	fmt.Println("1. Hosts")
	fmt.Println("2. Advertisement")
	fmt.Println("3. Malicious")
	fmt.Println("4. Social-Engineering")
	fmt.Println("5. Explicit")
	var userInput int
	fmt.Scanln(&userInput)
	// Set up the lists on your computer.
	hosts := "https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/hosts"
	advertisement := "https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/malicious"
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
		downloadFile(hosts, systemHostFile)
	case 2:
		downloadFile(advertisement, systemHostFile)
	case 3:
		downloadFile(malicious, systemHostFile)
	case 4:
		downloadFile(socialEngineering, systemHostFile)
	case 5:
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
	os.Remove(systemHostFile)
}

// Replace the URLs in this section to create your own list or add new lists.
func startScraping() {
	// Advertisement && Tracking
	advertisement := []string{
		"https://block.energized.pro/ultimate/formats/domains.txt",
		"https://raw.githubusercontent.com/259095/someonewhocares/main/list",
		"https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
		"https://raw.githubusercontent.com/DRSDavidSoft/additional-hosts/master/domains/blacklist/adservers-and-trackers.txt",
		"https://raw.githubusercontent.com/Ewpratten/youtube_ad_blocklist/master/blocklist.txt",
		"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
		"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt",
		"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
		"https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt",
		"https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Ads",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",
		"https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/cameleon_at_sysctl.org/master/domains.list",
		"https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts",
		"https://raw.githubusercontent.com/allendema/noplaylist/main/NoPlayList.txt",
		"https://raw.githubusercontent.com/anthony-wang/PiHoleBlocklist/master/hosts1.txt",
		"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
		"https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt",
		"https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/domains.txt",
		"https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt",
		"https://raw.githubusercontent.com/cbuijs/shallalist/master/adv/domains",
		"https://raw.githubusercontent.com/cbuijs/shallalist/master/tracker/domains",
		"https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt",
		"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/huawei-trackers.txt",
		"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/smart-tv-ads-tracking.txt",
		"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/smartphone-ads-tracking.txt",
		"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/spotify-ads-tracking.txt",
		"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/windows10-spying-erm-i-mean-telemetry-lol.txt",
		"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/xiaomi-ads-tracking.txt",
		"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/advertisement.txt",
		"https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
		"https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds-Ultra.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/adguarddns-justdomains.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easylist-justdomains.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/easyprivacy-justdomains.txt",
		"https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/black.list",
		"https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/huluads.txt",
		"https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/youtubelist.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/tracking-aggressive-extended.txt",
		"https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt",
		"https://raw.githubusercontent.com/mhhakim/pihole-blocklist/master/list.txt",
		"https://raw.githubusercontent.com/mhxion/pornaway/master/hosts/porn_ads.txt",
		"https://raw.githubusercontent.com/migueldemoura/ublock-umatrix-rulesets/master/Hosts/ads-tracking",
		"https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/domains.txt",
		"https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
		"https://raw.githubusercontent.com/ookangzheng/dbl-oisd-nl/master/dbl.txt",
		"https://raw.githubusercontent.com/ookangzheng/dbl-oisd-nl/master/hosts.txt",
		"https://raw.githubusercontent.com/tiuxo/hosts/master/ads",
		"https://raw.githubusercontent.com/xlimit91/xlimit91-block-list/master/blacklist.txt",
		"https://raw.githubusercontent.com/yous/YousList/master/hosts.txt",
	}
	// Malicious
	malicious := []string{
		"https://badmojr.github.io/1Hosts/Pro/domains.txt",
		"https://gitlab.com/andryou/block/raw/master/chibi-strict-domains",
		"https://gitlab.com/andryou/block/raw/master/kouhai-strict-domains",
		"https://gitlab.com/andryou/block/raw/master/senpai-strict-domains",
		"https://gitlab.com/curben/urlhaus-filter/-/raw/master/urlhaus-filter-domains.txt",
		"https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-blocklist.txt",
		"https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Regular%20Hosts.txt",
		"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
		"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
		"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Bloat",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/fakenews/hosts",
		"https://raw.githubusercontent.com/Strappazzon/teleme7ry/master/rules.txt",
		"https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/domains/domains0.list",
		"https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/domains/domains1.list",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/crypto.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/drugs.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/smart-tv.txt",
		"https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/newhosts-final.hosts",
		"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
		"https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
		"https://raw.githubusercontent.com/ftpmorph/ftprivacy/master/blocklists/avg-avast-data-mining-full-block.txt",
		"https://raw.githubusercontent.com/furkun/ProtectorHosts/main/hosts",
		"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/fraudulent.txt",
		"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/malware.txt",
		"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/ransomware.txt",
		"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/scam.txt",
		"https://raw.githubusercontent.com/herrbischoff/trackers/master/domains.txt",
		"https://raw.githubusercontent.com/infinitytec/blocklists/master/scams-and-phishing.txt",
		"https://raw.githubusercontent.com/justdomains/blocklists/master/lists/nocoin-justdomains.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/hate-and-junk-extended.txt",
		"https://raw.githubusercontent.com/matomo-org/referrer-spam-list/master/spammers.txt",
		"https://raw.githubusercontent.com/migueldemoura/ublock-umatrix-rulesets/master/Hosts/malware",
		"https://raw.githubusercontent.com/missdeer/blocklist/master/toblock-without-shorturl.lst",
		"https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
		"https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hosts",
		"https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains",
		"https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/alexa",
		"https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/apple",
		"https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/huawei",
		"https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/roku",
		"https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/samsung",
		"https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/sonos",
		"https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/windows",
		"https://raw.githubusercontent.com/nextdns/metadata/master/privacy/native/xiaomi",
		"https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt",
		"https://raw.githubusercontent.com/rimu/no-qanon/master/etc_hosts.txt",
		"https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestdomains.txt",
	}
	// Social Engineering
	socialEngineering := []string{
		"https://blocklist.cyberthreatcoalition.org/vetted/domain.txt",
		"https://phishing.army/download/phishing_army_blocklist_extended.txt",
		"https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/hosts.txt",
		"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/abuse.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
		"https://raw.githubusercontent.com/hemiipatu/PiHoleBlocklists/master/blocklists/phishing.txt",
		"https://raw.githubusercontent.com/merkleID/covid-domains/master/full-domains-list.txt",
		"https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
		"https://raw.githubusercontent.com/sk-cat/fluffy-blocklist/main/domains",
		"https://raw.githubusercontent.com/tg12/pihole-phishtank-list/master/list/phish_domains.txt",
	}
	// Adult content
	explicit := []string{
		"https://block.energized.pro/porn/formats/domains.txt",
		"https://block.energized.pro/extensions/porn-lite/formats/domains.txt",
		"https://raw.githubusercontent.com/4skinSkywalker/Anti-Porn-HOSTS-File/master/HOSTS.txt",
		"https://raw.githubusercontent.com/Bon-Appetit/porn-domains/master/block.txt",
		"https://raw.githubusercontent.com/Clefspeare13/pornhosts/master/0.0.0.0/hosts",
		"https://raw.githubusercontent.com/Import-External-Sources/pornhosts/master/download_here/0.0.0.0/hosts",
		"https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
		"https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
		"https://raw.githubusercontent.com/mhhakim/pihole-blocklist/master/porn.txt",
		"https://raw.githubusercontent.com/mhxion/pornaway/master/hosts/porn_sites.txt",
		"https://raw.githubusercontent.com/tiuxo/hosts/master/porn",
		"https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list",
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
	for i := 0; i < len(uniqueAdvertisement); i++ {
		if validURL(uniqueAdvertisement[i]) {
			scrapeWaitGroup.Add(1)
			// Begin searching and confirming the domains you've discovered.
			go findTheDomains(uniqueAdvertisement[i], advertisementConfig, advertisementArray)
			// To save memory, remove the string from the array.
			uniqueAdvertisement = removeStringFromSlice(uniqueAdvertisement, uniqueAdvertisement[i])
		}
	}
	if performance {
		scrapeWaitGroup.Wait()
	}
	// Malicious
	for i := 0; i < len(uniqueMalicious); i++ {
		if validURL(uniqueMalicious[i]) {
			scrapeWaitGroup.Add(1)
			// Begin looking for and verifying the domains you've found.
			go findTheDomains(uniqueMalicious[i], maliciousConfig, maliciousArray)
			// Remove it from the memory.
			uniqueMalicious = removeStringFromSlice(uniqueMalicious, uniqueMalicious[i])
		}
	}
	if performance {
		scrapeWaitGroup.Wait()
	}
	// Social Engineering
	for i := 0; i < len(uniqueSocialEngineering); i++ {
		if validURL(uniqueSocialEngineering[i]) {
			scrapeWaitGroup.Add(1)
			// Begin searching for and confirming the domains you've discovered.
			go findTheDomains(uniqueSocialEngineering[i], socialEngineeringConfig, socialEngineeringArray)
			// Remove it from memeory
			uniqueSocialEngineering = removeStringFromSlice(uniqueSocialEngineering, uniqueSocialEngineering[i])
		}
	}
	if performance {
		scrapeWaitGroup.Wait()
	}
	// Explicit
	for i := 0; i < len(uniqueExplicit); i++ {
		if validURL(uniqueExplicit[i]) {
			scrapeWaitGroup.Add(1)
			// Begin looking for and verifying the domains you've found.
			go findTheDomains(uniqueExplicit[i], explicitConfig, exclusionArray)
			// Remove it from memeory
			uniqueExplicit = removeStringFromSlice(uniqueExplicit, uniqueExplicit[i])
		}
	}
	scrapeWaitGroup.Wait()
	// Clear the memory via force.
	debug.FreeOSMemory()
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
	for a := 0; a < len(returnContent); a++ {
		// If the string begins with a "!", inform the user that it is most likely a browser-level ad block list rather than a domain-level ad block list.
		if strings.HasPrefix(string([]byte(returnContent[a])), "!") {
			if showLogs {
				log.Println("Error: Most likely, this is a browser-level block list rather than a DNS-level block list.", url)
			}
		}
		// Check to see if the string includes a # prefix, and if it does, skip it.
		if !strings.HasPrefix(string([]byte(returnContent[a])), "#") {
			// Make sure the domain is at least 3 characters long
			if len(string([]byte(returnContent[a]))) > 1 {
				// This is a list of all the domains discovered using the regex.
				foundDomains := regexp.MustCompile(`(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`).Find([]byte(returnContent[a]))
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
							// remove it from memory
							returnContent = removeStringFromSlice(returnContent, foundDomain)
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
	scrapeWaitGroup.Done()
	// While the validation is being performed, we wait.
	validationWaitGroup.Wait()
	debug.FreeOSMemory()
}

func validateTheDomains(uniqueDomains string, locatioToSave string) {
	if validation {
		// Validate each and every found domain.
		if validateDomainViaLookupNS(uniqueDomains) || validateDomainViaLookupAddr(uniqueDomains) || validateDomainViaLookupCNAME(uniqueDomains) || validateDomainViaLookupMX(uniqueDomains) || validateDomainViaLookupTXT(uniqueDomains) || validateDomainViaLookupHost(uniqueDomains) || domainRegistration(uniqueDomains) || validateDomainViaHTTP(uniqueDomains) {
			// Maintain a list of all authorized domains.
			writeToFile(locatioToSave, uniqueDomains)
			// Save it to all in one.
			writeToFile(allInOneBlockList, uniqueDomains)
			if showLogs {
				log.Println("Valid domain:", uniqueDomains)
			}
		} else {
			// Let the users know if there are any issues while verifying the domain.
			if showLogs {
				log.Println("Error validating domain:", uniqueDomains)
			}
		}
	} else {
		// To the list, add all of the domains.
		writeToFile(allInOneBlockList, uniqueDomains)
		// Add it to the list of one-of-a-kind items.
		writeToFile(locatioToSave, uniqueDomains)
		if showLogs {
			log.Println("Domain:", uniqueDomains)
		}
	}
	debug.FreeOSMemory()
	// When it's finished, we'll be able to inform waitgroup that it's finished.
	validationWaitGroup.Done()
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

// Make an HTTP request to the website to see whether it's up and running.
func validateDomainViaHTTP(domain string) bool {
	httpValue := fmt.Sprint("http://" + domain)
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
	for i := 0; i < len(originalSlice); i++ {
		// if the array matches with the string, you remove it from the array
		if originalSlice[i] == removeString {
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
		// It should be removed from the array memeory.
		uniqueDomains = removeStringFromSlice(uniqueDomains, uniqueDomains[i])
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
	os.Remove(filePath)
	for a := 0; a < len(returnContent); a++ {
		contentToWrite := fmt.Sprintln("0.0.0.0", returnContent[a])
		writeToFile(filePath, contentToWrite)
		returnContent = removeStringFromSlice(returnContent, returnContent[a])
	}
	// Get as much free memoey as possible from the system.
	returnContent = nil
	debug.FreeOSMemory()
}
