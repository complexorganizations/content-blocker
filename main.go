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
	combinedHost   = "configs/hosts"
	localExclusion = "configs/exclusion"
	localInclusion = "configs/inclusion"
	// Memorandum with a domain list.
	exclusionDomains []string
	// Go routines using waitgrops.
	scrapeWaitGroup     sync.WaitGroup
	validationWaitGroup sync.WaitGroup
	uniqueWaitGroup     sync.WaitGroup
	cleanUpWaitGroup    sync.WaitGroup
	// The user expresses his or her opinion on what should be done.
	showLogs  bool
	update    bool
	install   bool
	uninstall bool
	search    string
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
		tempSearch := flag.String("search", "example.example", "Check to see if a specific domain is on a list.")
		flag.Parse()
		update = *tempUpdate
		showLogs = *tempLog
		install = *tempInstall
		uninstall = *tempUninstall
		search = *tempSearch
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
		updateTheLists()
	}
	// Search
	if len(search) > 1 && search != "example.example" {
		findAllMatchingDomains(search)
	}
}

// Configure your system to use the lists.
func installInSystem() {
	var systemHostFile string
	switch runtime.GOOS {
	case "windows":
		systemHostFile = `C:\Windows\System32\drivers\etc\hosts`
	case "darwin", "linux":
		systemHostFile = "/etc/hosts"
	}
	// Install in your system.
	if !fileExists(systemHostFile) {
		writeHostFile(combinedHost, systemHostFile)
	} else {
		log.Fatal("Error: There is already a system host file presnet.")
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
	if fileExists(systemHostFile) {
		err = os.Remove(systemHostFile)
		if err != nil {
			log.Println(err)
		}
	}
}

func updateTheLists() {
	// Clear your memories as much as possible
	if folderExists(os.TempDir()) {
		os.RemoveAll(os.TempDir())
		os.Mkdir(os.TempDir(), 0777)
	} else {
		log.Println("Error: The system temporary directory could not be found.")
	}
	debug.FreeOSMemory()
	// Max ammount of go routines
	debug.SetMaxThreads(10000)
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
	cleanUpWaitGroup.Wait()
}

// Replace the URLs in this section to create your own list or add new lists.
func startScraping() {
	combinedHostsURL := []string{
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
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
	var returnContent []string
	for scanner.Scan() {
		returnContent = append(returnContent, scanner.Text())
	}
	// When you're finished, close the body.
	response.Body.Close()
	for _, content := range returnContent {
		// If the string begins with a "!", "|" inform the user that it is most likely a browser-level ad block list rather than a domain-level ad block list.
		if strings.HasPrefix(content, "!") || strings.HasPrefix(content, "|") {
			log.Println("Error: Most likely, this is a browser-level block list rather than a DNS-level block list.", url)
		}
		// Check to see if the string includes a # prefix, and if it does, skip it.
		if !strings.HasPrefix(content, "#") {
			// Make sure the domain is at least 3 characters long
			if len(content) > 1 {
				// Remove any forwarding hosts from the string here.
				if strings.HasPrefix(content, "0.0.0.0") || strings.HasPrefix(content, "127.0.0.1") {
					// If any forwarding hosts are discovered, they should be removed.
					content = strings.TrimPrefix(content, "0.0.0.0")
					content = strings.TrimPrefix(content, "127.0.0.1")
					// Remove any `.` from the prefix for the supplied text.
					content = strings.TrimPrefix(content, ".")
					// If the string has any whitespace, remove it now.
					content = strings.TrimSpace(content)
				}
				// This is a list of all the domains discovered using the regex.
				foundDomains := regexp.MustCompile(`(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`).Find([]byte(content))
				// all domains discovered with the regexp
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
	// While the validation is being performed, we wait.
	validationWaitGroup.Wait()
	scrapeWaitGroup.Done()
	debug.FreeOSMemory()
}

func validateTheDomains(uniqueDomain string, locatioToSave string) {
	// Validate each and every found domain.
	if validateDomainViaLookupNS(uniqueDomain) || validateDomainViaLookupIP(uniqueDomain) || validateDomainViaLookupCNAME(uniqueDomain) || validateDomainViaLookupHost(uniqueDomain) || domainRegistration(uniqueDomain) {
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

// Find all the matching domains in your lists
func findAllMatchingDomains(domain string) {
	// combined
	var combinedConfigArray []string
	combinedConfigArray = readAndAppend(combinedHost, combinedConfigArray)
	for _, content := range combinedConfigArray {
		// if the array matches with the string, you remove it from the array
		if strings.Contains(content, domain) {
			fmt.Println("Found Domain:", content, "Location:", combinedHost)
		}
	}
	// Exclusion
	var localExclusionArray []string
	localExclusionArray = readAndAppend(localExclusion, localExclusionArray)
	for _, content := range localExclusionArray {
		if strings.Contains(content, domain) {
			fmt.Println("Found Domain:", content, "Location:", localExclusion)
		}
	}
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

// Using cname, verify the domain.
func validateDomainViaLookupCNAME(domain string) bool {
	valid, _ := net.LookupCNAME(domain)
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
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// Check to see whether the folder already exists.
func folderExists(foldername string) bool {
	info, err := os.Stat(foldername)
	if err != nil {
		return false
	}
	return info.IsDir()
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

// Download a file in your system
func writeHostFile(configPath string, filePath string) {
	// Scraped data is read and appended to an array.
	var returnContent []string
	returnContent = readAndAppend(configPath, returnContent)
	// Remove the original file before rewriting it.
	if fileExists(filePath) {
		err = os.Remove(filePath)
		if err != nil {
			log.Println(err)
		}
	}
	for _, content := range returnContent {
		trimmedContent := strings.Trim(content, " ")
		contentToWrite := fmt.Sprintln("0.0.0.0", trimmedContent)
		writeToFile(configPath, contentToWrite)
	}
	// Get as much free memoey as possible from the system.
	returnContent = nil
	debug.FreeOSMemory()
}

// Write the inclusion without validating it.
func copyContentFromOneFileToAnother(originalFilePath string, newFilePath string) {
	var originalContent []string
	originalContent = readAndAppend(originalFilePath, originalContent)
	for _, content := range originalContent {
		writeToFile(newFilePath, content)
	}
}
