# content-blocker

You can restrict any material you want on a DNS level.

***content-blocker is not yet complete. You should not rely on this code. It has not undergone proper degrees of security auditing and the protocol is still subject to change. We're working toward a stable 1.0.0 release, but that time has not yet come. There are experimental snapshots tagged with "0.0.0.MM-DD-YYYY", but these should not be considered real releases and they may contain security vulnerabilities (which would not be eligible for CVEs, since this is pre-release snapshot software). If you are packaging content-blocker, you must keep up to date with the snapshots.***

#### Note: I'm looking for assistance in identifying more lists that prohibit ADs.

#### Get all items

## Features

- On a DNS level, it blocks the majority of advertising, malicious, social-engineering.
- Save your data since the DNS servers will not load for ads, leaving your device with no adverts to download.

```http
  GET https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/hosts
```

| Type     | Description                |
| :------- | :------------------------- |
| Everything | https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/hosts |
| Advertisement | https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/hosts |
| Malicious | https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/malicious |
| Social-Engineering | https://raw.githubusercontent.com/complexorganizations/content-blocker/main/configs/social-engineering |


### Creating and updating a list
Let's begin by cloning the repository.
```
git clone --depth 1 https://github.com/complexorganizations/content-blocker
```
Let's make a new list.
```
go run main.go
```


### Q&A
What's the best way for me to make my own list?
- Open the repo after forking and cloning it. Go ahead and change the struct in `startScraping`, replacing the urls there with the lists you wish to use, and then just run the file using the command `go run main.go`.

What's the best way to add my own exclusions?
- Simply open the `configs/exclusion` file, add a domain, and submit a pull request; if your pull request is merged, the domain will be excluded the next time the list is updated.

Is the list updated on a regular basis?
- We strive to update the list every 24 hours, but this cannot be guaranteed, and if it is not updated for any reason please let us know.

Why are you only banning it on the DNS level rather than the system level?
- It's a good idea to prohibit something on a system level rather than a DNS level, however some devices can't prohibit it on a system level (for example, smart devices), therefore a dns level is preferred.

How can I get credit if I own one of the lists you're using?
- Please make a pull request.

Is it possible for you to remove my domain off the blacklist if I pay you?
- No

What's the best way to get my list in here?
- To be considered for inclusion, your list must be updated at least once every 30 days and contain at least 500 domains.

### Credits
Open Source Community

| Author                 | URL                    | License                |
| ---------------------  | ---------------------  | ---------------------  |
| Steven-Black-Ads       | https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | MIT |
| Light-Switch-Ads       | https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt | Apache License 2.0 |
| Notracking-Trackers    | https://raw.githubusercontent.com/notracking/hosts-blocklists/master/unbound/unbound.blacklist.conf | UNKNOWN |
|                        |                        |                        |


## Support

Please utilize the github repo issue and wiki for help.


## Feedback

Please utilize the github repo conversations to offer feedback.


## License
Copyright © [Prajwal](https://github.com/prajwal-koirala)

This project is unlicensed.
