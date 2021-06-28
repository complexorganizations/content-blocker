# content-blocker

<p align="center">
	<a href="https://github.com/complexorganizations/content-blocker/actions/workflows/auto-update.yml">
		<img alt="Update" src="https://github.com/complexorganizations/content-blocker/actions/workflows/auto-update.yml/badge.svg" target="_blank" />
	</a>
</p>

Content blocker is a DNS level blocker that can block anything on the DNS level, eliminating the need for the user to download an additional application. It works on internet of things devices.

### Features

- content blocker is a general purpose blocker that can block practically anything on the internet, but is most commonly used to block advertisements, tracking, and pornography.
- DNS queries on the DNS server are canceled, saving bandwidth.

### Goals
- Lists containing valid hosts that have been unified.
- Domains and subdomains that are duplicated are removed from the list.

### Variants
| Name     | Description                | URL      | Mirror   |
| :------- | :------------------------- | :------- | :------- |
| Hosts    | Advertisement, Malicious, Social-Engineering, Explicit | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/hosts` | `https://gitlab.com/prajwal-koirala/content-blocker/-/raw/main/configs/hosts` |
| Advertisement | Advertisement, Tracking | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/advertisement` | `https://gitlab.com/prajwal-koirala/content-blocker/-/raw/main/configs/advertisement` |
| Malicious | Malware, Spyware | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/malicious` | `https://gitlab.com/prajwal-koirala/content-blocker/-/raw/main/configs/malicious` |
| Social-Engineering | Phishing, Scams, Fake News | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/social-engineering` | `https://gitlab.com/prajwal-koirala/content-blocker/-/raw/main/configs/social-engineering` |
| Explicit | Sexual content | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/explicit` | `https://gitlab.com/prajwal-koirala/content-blocker/-/raw/main/configs/explicit` |

---
#### Instead of a DNS server, install the list on your machine.
Let's get the app on your computer.
```
git clone --depth 1 https://github.com/complexorganizations/content-blocker
```
Let's get the lists set up in your system.
```
go run main.go -install
```

#### Creating and updating a list
Let's begin by cloning the repository.
```
git clone --depth 1 https://github.com/complexorganizations/content-blocker
```
Make a new, up-to-date list.
```
go run main.go -update -validation
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
- Open the repo after forking and cloning it. Go ahead and change the struct in `startScraping`, replacing the urls there with the lists you wish to use, and then just run the file using the command `go run main.go`.

Note: If you want to create your own list(s), please utilize a server; otherwise, your system resources will be depleted.

What's the best way to add my own exclusions?
- Simply open the `configs/exclusion` file, add a domain, and submit a pull request; if your pull request is merged, the domain will be excluded the next time the list is updated.

Is the list updated on a regular basis?
- We strive to update the list(s) every day, but this cannot be guaranteed, and if it is not updated for any reason please let us know.

Why are you only banning it on the DNS level rather than the system level?
- It's a good idea to prohibit something on a system level rather than a DNS level, however some devices can't prohibit it on a system level (for example, smart devices), therefore a dns level is preferred.

How can I get credit if I own one of the lists you're using?
- Please make a pull request.

Is it possible for you to remove my domain off the blacklist if I pay you?
- No

What's the best way to get my list(s) in here?
- There are no special requirements for submitting your list(s) to the repo, however we do urge that they be of good quality and updated on a regular basis.

What's the most efficient method for me to get my list(s) out of here?
- Make the list(s) private so we can't scrape the information out of them.

Why isn't there a list of IP addresses?
- They may simply go on to the next IP and continue from there, thus banning IPs is worthless.

What is the procedure for creating a new category?
- Creating new categories is strongly discouraged, and no longer receives support; nevertheless, if you still believe it is essential for the community, please open an issue.

What are the reasons behind the exclusion of so many financial domains and subdomains?
- We just erase such entries if any of the list authors try to mess with them.

Why doesn't your repo have a git history?
- We would top out github's limits, under a day due to huge amounts of change.

---
#### Credits
Open Source Community

| Author                 | Repository             | License                |
| ---------------------  | ---------------------  | ---------------------  |
| StevenBlack            | `https://github.com/StevenBlack/hosts` | MIT |
| LightSwitch            | `https://github.com/lightswitch05/hosts` | Apache License 2.0 |
| Notracking             | `https://github.com/notracking/hosts-blocklists` | UNKNOWN |
| AdAway                 | `https://github.com/AdAway/AdAway` | GPLv3+     |
| DRSDavidSoft           | `https://github.com/DRSDavidSoft/additional-hosts` | MIT |
| Ewpratten              | `https://github.com/Ewpratten/youtube_ad_blocklist` | GPLv3+ |
| Perflyst               | `https://github.com/Perflyst/PiHoleBlocklist` | `MIT` |
|                        |                        |                        |

#### Support
Please utilize the github repo issue and wiki for help.

#### Feedback
Please utilize the github repo conversations to offer feedback.

#### License
Copyright © [Prajwal](https://github.com/prajwal-koirala)

This project is unlicensed.
