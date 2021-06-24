# content-blocker

<p align="center">
	<a href="https://github.com/complexorganizations/content-blocker/actions/workflows/auto-update.yml">
		<img alt="Update" src="https://github.com/complexorganizations/content-blocker/actions/workflows/auto-update.yml/badge.svg" target="_blank" />
	</a>
</p>

Content blocker is a DNS level blocker that can block anything on the DNS level, eliminating the need for the user to download an additional application. It works on internet of things devices.

## Features

- content blocker is a general purpose blocker that can block practically anything on the internet, but is most commonly used to block advertisements, tracking, and pornography.
- DNS queries on the DNS server are canceled, saving bandwidth.

### Variants
| Name     | Description                | URL      |
| :------- | :------------------------- | :------- |
| Hosts    | Advertisement, Malicious, Social-Engineering, Explicit | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/hosts` |
| Advertisement | Advertisement, Tracking | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/advertisement` |
| Malicious | Malware, Spyware | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/malicious` |
| Social-Engineering | Phishing, Scams, Fake News | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/social-engineering` |
| Explicit | Sexual content | `https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/explicit` |

### Instead of a DNS server, install the list on your machine.
Let's get the app on your computer.
```
git clone --depth 1 https://github.com/complexorganizations/content-blocker
```
Let's get the lists set up in your system.
```
go run main.go -install
```

### Creating and updating a list
Let's begin by cloning the repository.
```
git clone --depth 1 https://github.com/complexorganizations/content-blocker
```
Make a new, up-to-date list.
```
go run main.go -update
```

### Q&A
What's the best way for me to make my own list?
- Open the repo after forking and cloning it. Go ahead and change the struct in `startScraping`, replacing the urls there with the lists you wish to use, and then just run the file using the command `go run main.go`.

What's the best way to add my own exclusions?
- Simply open the `configs/exclusion` file, add a domain, and submit a pull request; if your pull request is merged, the domain will be excluded the next time the list is updated.

Is the list updated on a regular basis?
- We strive to update the list every 12 hours, but this cannot be guaranteed, and if it is not updated for any reason please let us know.

Why are you only banning it on the DNS level rather than the system level?
- It's a good idea to prohibit something on a system level rather than a DNS level, however some devices can't prohibit it on a system level (for example, smart devices), therefore a dns level is preferred.

How can I get credit if I own one of the lists you're using?
- Please make a pull request.

Is it possible for you to remove my domain off the blacklist if I pay you?
- No

What's the best way to get my list in here?
- To be considered for inclusion, your list must be updated at least once every 30 days and contain at least 500 domains.

Why isn't there a list of IP addresses?
- They may simply go on to the next IP and continue from there, thus banning IPs is worthless.

### Credits
Open Source Community

| Author                 | Repository             | License                |
| ---------------------  | ---------------------  | ---------------------  |
| Steven-Black           | `https://github.com/StevenBlack/hosts` | MIT |
| Light-Switch           | `https://github.com/lightswitch05/hosts` | Apache License 2.0 |
| Notracking             | `https://github.com/notracking/hosts-blocklists` | UNKNOWN |
|                        |                        |                        |


## Support

Please utilize the github repo issue and wiki for help.


## Feedback

Please utilize the github repo conversations to offer feedback.


## License
Copyright © [Prajwal](https://github.com/prajwal-koirala)

This project is unlicensed.
