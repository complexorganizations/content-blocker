# content-blocker

[![Updating the resources](https://github.com/complexorganizations/content-blocker/actions/workflows/auto-update.yml/badge.svg)](https://github.com/complexorganizations/content-blocker/actions/workflows/auto-update.yml)

Content blocker is a DNS level blocker that can block anything on the DNS level, removing the need for the user to download a separate program.

### Note: Please report domains if you wish to help with the project.

---
### Features

- content blocker is a general purpose blocker that can block practically anything on the internet, but is most commonly used to block advertisements, tracking, and malware.
- DNS queries on the DNS server are canceled, saving bandwidth.

---
### Goals
- Lists containing valid hosts that have been unified.
- Domains and subdomains that are duplicated are removed from the list.

---
### Variants
| Name     | Description                | URL      | Mirror   |
| :------- | :------------------------- | :------- | :------- |
| Hosts | Advertisement, Tracking, Malware, Phishing | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/assets/hosts` | `https://gitlab.com/prajwal-koirala/content-blocker/-/raw/main/assets/hosts` |

---
Let's begin by copying the repository to your own machine.
```
git clone --depth 1 https://github.com/complexorganizations/content-blocker
```

#### Instead of a DNS server, install the list on your machine.
Let's get the lists set up in your system.
```
go run main.go -install
```

#### Creating and updating a list
Make a new, up-to-date list.
```
go run main.go -update
```

#### Locating a certain domain in the list(s)
Then we're ready to go on the hunt.
```
go run main.go -search="example.com"
```

---
#### Compatibility
| Operating System(s)    | Tested                 |
| ---------------------  | ---------------------  |
| Linux                  | :heavy_check_mark:     |
| Windows                | :heavy_check_mark:     |
| MacOS                  | :heavy_check_mark:     |
| Android                | :heavy_check_mark:     |
| iOS                    | :heavy_check_mark:     |

---
## Q&A
What's the best way for me to make my own list?
- Open the repo after cloning it. Go ahead and change the struct in `startScraping`, replacing the urls there with the lists you wish to use, and then just run the file using the command `go run main.go`.

What's the best way to add my own exclusions?
- Simply open the `assets/exclusion` file, add a domain, and submit a pull request; if your pull request is merged, the domain will be excluded the next time the list is updated.

Is the list updated on a regular basis?
- We strive to update the list(s) every day, but this cannot be guaranteed, and if it is not updated for any reason please let us know.

Why are you only banning it on the DNS level rather than the system level?
- It's a good idea to prohibit something on a system level rather than a DNS level, however some devices can't prohibit it on a system level (for example, smart devices), therefore a dns level is preferred.

Is it possible for you to remove my domain off the blacklist if I pay you?
- No

How can I ensure that my domain isn't included in your list(s)?
- For someone's domain to be removed off the list(s), we simply have one requirement: high quality content.

Why isn't there a list of IP addresses?
- They may simply go on to the next IP and continue from there, thus banning IPs is worthless.

Why aren't you using regex to find them all instead of going line by line?
- While using regex to discover them all is extremely cost effective, this method will not work on all domains, leaving you with a broken domain.

What percentage of domains aren't working?
- It's usually about 0% because every single domain is validated before being added to the list.

Why are exclusion && hosts file(s) not retrieved from the url?
- The issue with obtaining it from a url is that if you want to add your own local domains, it must be part of the official repository.

If I installed it, how would I uninstall it?
- `go run main.go -uninstall`

Why are the lists so small?
- Rather than relays, we're attempting to block central distribution networks.

Why don't you prohibit subdomains?
- Companies like to establish hundreds of subdomains to get around prohibitions because creating new subdomains is free.

Why aren't you utilizing one of the existing lists?
- We are not using any of these lists because we want to provide a new, up-to-date list.

Which content blocker do you recommend for use in a browser?
- [uBlock Origin](https://github.com/gorhill/uBlock)

What method is used to create these lists?
<p align="center">
  <img src="https://raw.githubusercontent.com/complexorganizations/content-blocker/main/assets/content-blocker.png" alt="Lists Creation"/>
</p>

---
### Roadmap
- Add new domains to the list of domains that must be validated.

---
#### System Requirements
- Memory: 1GB
- Operating system: Windows, Linux, MacOS, Android, iOS...
- Disk space: 500 MB

---
#### Credits
Open Source Community

---
#### Support
Please utilize the github repo issue and wiki for help.

#### Feedback
Please utilize the github repo conversations to offer feedback.

#### License
Copyright © [Prajwal](https://github.com/prajwal-koirala)

The Apache 2.0 license governs the distribution of this project.
