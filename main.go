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
	"runtime/debug"
	"sort"
	"strings"
	"sync"

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
	savedDomains     []string
	// Go routines using waitgrops.
	scrapeWaitGroup     sync.WaitGroup
	validationWaitGroup sync.WaitGroup
	uniqueWaitGroup     sync.WaitGroup
	cleanUpWaitGroup    sync.WaitGroup
	// The user expresses his or her opinion on what should be done.
	update bool
	search string
	// err stands for error.
	err error
)

func init() {
	// If any user input flags are provided, use them.
	if len(os.Args) > 1 {
		tempUpdate := flag.Bool("update", false, "Make any necessary changes to the listings.")
		tempSearch := flag.String("search", "example.example", "Check to see if a specific domain is on a list.")
		flag.Parse()
		update = *tempUpdate
		search = *tempSearch
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
	// Search
	if len(search) > 1 && search != "example.example" {
		findAllMatchingDomains(search)
	}
}

func updateTheLists() {
	// Clear your memories as much as possible
	if folderExists(os.TempDir()) {
		err := os.RemoveAll(os.TempDir())
		if err != nil {
			log.Println(err)
		}
		err = os.Mkdir(os.TempDir(), 0777)
		if err != nil {
			log.Println(err)
		}
	} else {
		log.Println("Error: The system temporary directory could not be found.")
	}
	// Force clear your system memory.
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
		"https://raw.githubusercontent.com/complexorganizations/content-blocker/main/assets/validate",
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
	err = response.Body.Close()
	if err != nil {
		log.Fatalln(err)
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
			// Remove any whitespace from the string.
			content = strings.TrimSpace(content)
			// Validate the entire list of domains.
			if len(content) < 255 && isDomainSuffixValid(content) {
				validationWaitGroup.Add(1)
				// Go ahead and verify it in the background.
				go validateTheDomains(content, saveLocation)
			} else {
				// Let the user know that the domain is invalid since it does not fit the syntax.
				log.Println("Invalid domain syntax:", content, url)
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

func validateTheDomains(uniqueDomain string, locatioToSave string) {
	// Maintain a list of all authorized domains.
	if !arrayContains(savedDomains, uniqueDomain) {
		// Only validate the domain once.
		savedDomains = append(savedDomains, uniqueDomain)
		// Validate each and every found domain.
		if isDomainRegistered(uniqueDomain) {
			writeToFile(locatioToSave, uniqueDomain)
		} else {
			log.Println("Error validation the domain regestration:", uniqueDomain)
		}
	} else {
		// Let the users know if there are any issues while verifying the domain.
		log.Println("Error duplicate domain found:", uniqueDomain)
	}
	// When it's finished, we'll be able to inform waitgroup that it's finished.
	validationWaitGroup.Done()
}

// Find all the matching domains in your lists
func findAllMatchingDomains(domain string) {
	// Combined
	var combinedConfigArray []string
	combinedConfigArray = readAndAppend(combinedHost, combinedConfigArray)
	for _, content := range combinedConfigArray {
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
	_, err := net.LookupNS(domain)
	if err == nil {
		return true
	}
	_, err = net.LookupCNAME(domain)
	if err == nil {
		return true
	}
	_, err = net.LookupAddr(domain)
	if err == nil {
		return true
	}
	_, err = net.LookupHost(domain)
	if err == nil {
		return true
	}
	_, err = net.LookupMX(domain)
	if err == nil {
		return true
	}
	_, err = net.LookupTXT(domain)
	if err == nil {
		return true
	}
	_, err = net.LookupIP(domain)
	if err == nil {
		return true
	}
	return false
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
	}
	// write the content to the file
	_, err = filePath.WriteString(content + "\n")
	if err != nil {
		log.Println(err)
	}
	// close the file
	filePath.Close()
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
	// close the file
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
	browserHeaderContent := `! Title: Content Blocker - Advanced Tracker and Analytics Blocker
	! Description: This robust filter is meticulously designed to fortify your online privacy by intercepting and blocking a wide array of trackers, web analytics tools, and data collectors, ensuring a more secure and confidential browsing experience. Stay protected and in control of your digital footprint with this comprehensive shield against intrusive tracking mechanisms.
	! Version: 1.0.0
	! Last updated: %timestamp%
	! Update frequency: Daily
	! Homepage: https://github.com/complexorganizations/content-blocker
	! License: https://github.com/complexorganizations/content-blocker/main/.github/license
	! Support: https://github.com/complexorganizations/content-blocker/issues`
	writeToFile(combinedBrowser, browserHeaderContent)
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
		log.Fatalln(err)
	}
	return domain
}
