---
title: "Absurdities Part-1: Chrome Secrets & Defender Bypasses"
description: "A deep dive into Chrome's key protections and how Defendnot fakes antivirus registration to bypass Windows Defender."
date: 2025-06-30
classes: wide
toc: true
toc_label: "Table of contents"
header:
    teaser: /assets/images/Absurdities/maain.png
ribbon: green
categories:
    - Absurdities
tags:
    - Chrome
    - Defendnot
---
# Introduction
I've decided to challenge myself by launching a series of blog posts that explore various techniques commonly used by malware and advanced persistent threats (APTs). Each post will be concise, easy to follow, and focused on a specific technique. To add practical value, I'll include suggested detection methods—whether through static analysis using YARA rules, or dynamic approaches involving API monitoring and behavioral triggers (such as file, registry, or network events).

The goals of this series are threefold:

* To push myself beyond my comfort zone and deepen my technical knowledge.
* To share new/interesting techniques (From my perspective)
* To engage with the cybersecurity community and refine my detection strategies through feedback and discussion.

# Why is it called "Absurdities"?
The title "Absurdities" reflects the intentionally unconventional nature of this blog series. Each post will explore two or more unrelated techniques—sometimes odd, unexpected, or seemingly disconnected. While the techniques themselves may appear "absurd" when grouped together, the unifying theme is how to detect them effectively.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/absurditites.gif" caption="Figure 1: Donald Trump" %}

# Summary
In this post, we'll explore two distinct techniques often encountered in the context of malware analysis and infostealers:

1. _**Chrome's Security Mechanisms**_ - We'll examine how Chrome secures sensitive user data such as cookies, saved passwords, and credit card information, and how infostealers can bypass these protections to exfiltrate that data.

2. _**Fake Antivirus Registration**_ - We'll dive into how some malware samples evade detection by registering themselves as a fake antivirus (AV) provider. This deceptive technique allows malware to interfere with legitimate security tools and reduce the chances of being flagged or removed.

# Absurdity-I: Chrome's Security Mechanisms
## DPAPI
Chrome relies on the Windows Data Protection API (DPAPI) to encrypt and decrypt sensitive data stored locally, such as cookies and saved passwords. DPAPI is a built-in Windows feature designed to provide secure data encryption without requiring developers to implement their own cryptographic algorithms.

The encryption and decryption processes are handled through two core functions exported by `CRYPT32.DLL`:

* `CryptProtectData` - Used to encrypt (protect) data.
* `CryptUnprotectData` - Used to decrypt (unprotect) data.

## How Infostealer can Abuse DPAPI
### SnakeKeylogger:
`SnakeKeylogger` is a relatively credential stealer and keylogger first identified in the wild in November 2020. Implemented in .NET, it's a modular malware designed to perform a range of malicious activities, including logging keystrokes, exfiltrating saved credentials, capturing screenshots, and collecting data from the clipboard, all of which is subsequently transmitted back to the attacker.

The malware typically propagates through phishing and spear-phish campaigns. Victims receive a phishing email with a malicious Office document or PDF attached. Once the recipient opens the document and enables macros, or if they are using a vulnerable version of Office or their PDF reader, the malware is triggered and executes its routines.

Lets take deep look in this sample (MD5: `dcbb3564554b631e94695f3723c27dc2`)

{% include my_figure.html src="/assets/images/Absurdities/Part-1/DPAPI_Decrypting CookiesFlow.png" caption="Figure 2: Cookies Decryption Flow" %}

The malware first examines Chrome's cookie database to determine the encryption version. Specifically, it checks if the cookie entries start with the prefix `v10`, which denotes an older format used by Chrome to store encrypted cookies within the `encrypted_value` column, as shown in the following table schema:

```sql
CREATE TABLE cookies (
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    host_key TEXT NOT NULL,
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    is_httponly INTEGER NOT NULL,
    encrypted_value BLOB DEFAULT ''  -- Encrypted Cookies
);
```
If the format is older than `v10`, the sample directly uses Windows DPAPI (via `CryptUnprotectData`) to decrypt the `encrypted_value`.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/DPAPI_checkCookiesVersion.png" caption="Figure 3: SnakeKeylogger checks cookies version" %}

However, if the format is `v10`, the malware follows Chrome's updated encryption model:

***<u>Retrieving the AES Key</u>***: The malware first reads the `Local State` file located in Chrome's user data directory. This file contains the `encrypted_key` field, which holds the encoded AES Key. In the case of format `v10`, this key is encrypted using AES algorithm.

***<u>Decrypting the AES Key</u>***: Snake uses the Windows API function `UnprotectData` which internally uses `CryptUnprotectData` to decrypt the `encrypted_key` value and then decode it using Base64 to retrieve the raw AES key.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/DPAPI_getEncryptedAESKeyFromCookies.png" caption="Figure 4: SnakeKeylogger decrypts AES key using UnprotectData" %}

***<u>Initializing AES Decryption</u>***: After obtaining the raw AES key, Snake imports it using Windows Cryptography API to:
    * Convert the raw key into a usable Key BLOB using `BCryptImportKey`
    * Set the chaining mode to Galois/Counter Mode (GCM) for AES

{% include my_figure.html src="/assets/images/Absurdities/Part-1/DPAPI_initalizeAESKeyModeGCM.png" caption="Figure 5: SnakeKeylogger initializes AES key with mode of ChainingModeGCM" %}

***<u>Decrypting the Cookies</u>***: Finally, it uses `BCryptDecrypt` to decrypt each cookie value from Chrome's database using the previously imported AES key.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/DPAPI_Decrypting Cookies.png" caption="Figure 6: SnakeKeylogger decrypts cookies" %}


## App-Bound Encryption

With the release of Chrome 127 (July 2024), Google introduced Application-Bound Encryption to resolve the weakness in Windows' DPAPI model. This new mechanism significantly strengthens the protection of sensitive data such as cookies, passwords, and tokens.

Unlike traditional DPAPI, where decryption could be performed as long as the malware runs under the same user context, App-Bound Encryption requires that decryption requests originate from a validated Chrome process itself or from a process running inside Chrome's path.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/appBound_ChromeDecryptKey.png" caption="Figure 7: App-Bound Encryption/Decryption Flow. Source: https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html" %}

So, how Stealer (User-Access) could abuse it. Although the decryption is now handled by a SYSTEM-level process, communication between user-level malware and this process is still possible via COM (Component Object Model) by attempting to initiate a COM object tied to Chrome's decryption infrastructure:

* CLSID: `708860E0-F641-4611-8895-7D867DD3675B` (GoogleChromeElevationService)
* IID: `463ABECF-410D-407F-8AF5-0DF35A005CC8` (Interface ID for data decryption)

{% include my_figure.html src="/assets/images/Absurdities/Part-1/appBound_DecryptViaCOM.png" caption="Figure 8: Decrypting App-Bound Key of Chrome via COM" %}

Here are CLSID/IID of other chromium-based browsers:
* Microsoft Edge
    * CLSID: `1FCBE96C-1697-43AF-9140-2897C7C69767`
    * IID: `C9C2B807-7731-4F34-81B7-44FF7779522B`

* Brave Browser
    * CLSID: `576B31AF-6369-4B6B-8560-E4B203A97A8B`
    * IID: `F396861E-0C8E-4C71-8256-2FAE6D759CE9`

## How Infostealer can Abuse App-Bound
### Glove Stealer: (COM Elevation Service)

Glove Stealer is a .NET-based Windows infostealer discovered on November 2024, named for its ability to "slip through" Chrome's App-Bound Encryption which is delivered via phishing campaigns using `ClickFix-style HTML attachments—malicious` scripts instruct users to run PowerShell or Run commands, triggering the download and execution of the stealer.

Lets take deep look in this sample (Stealer MD5: `7063ad10bd5a92e76f6ec040e1610241`, App-Bound Decryptor MD5: `cda9a7821105d51b81a32f9167c042b0`)

{% include my_figure.html src="/assets/images/Absurdities/Part-1/appBound_gloveStealerFlow.png" caption="Figure 9: Glove Stealer Flow" %}

The stealer begins by locating the Chrome installation path, which is a critical prerequisite for a successful App-Bound decryption attempt. To achieve this, it searches for the `elevation_service.exe` binary—part of the official `GoogleChromeElevationService`. This step is essential because even if the decryption component runs with SYSTEM privileges, the App-Bound decryption mechanism will fail if the process is not executed from within the legitimate Chrome directory.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/appBound_getChromePath.png" caption="Figure 10: Get Chrome Path to download App-Bound Decryptor inside" %}

Once the correct Chrome path is identified, the stealer proceeds to download a custom decryption payload from its command-and-control (C2) server `https[:]//master.volt-texs[.]online/postovoy/[RandomString]`

The payload is saved into Chrome's main directory under the name `zagent.exe`, ensuring it inherits the correct execution context required to interact with the App-Bound decryption service.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/appBound_DownloadStartAppboundDecryptor.png" caption="Figure 11: Download and start App-Bound Decryptor" %}

Once the downloaded decryptor `zagent.exe` is placed inside the Chrome directory and executed, it proceeds to extract the App-Bound encryption key from Chrome's `Local State` file—similar to the process described earlier with DPAPI-based decryption.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/appBound_DecodeEncryptedAppBoundKey.png" caption="Figure 12: Get Encrypted App-Bound Key" %}

Finally, it will create a COM object as discussed previously to decrypt the App-Bound key using `DecryptData` method and save the decrypted key in `chromekey.txt` file inside `Recents` directory.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/appBound_decryptEncryptedAppBoundKey.png" caption="Figure 13: Decrypt App-Bound Key" %}


### Detection Rule:
Let's create a rule to detect decryption of cookies using App-Bound mechanism. I will create CAPE/Cuckoo-style rule which is based on intercepting API calls to parse their arguments and then trigger on some conditions.

Before creating our rule, we need to identify some concepts about CAPE-style rules. There are 2 methods of a rule:

* `on_call`: It's a callback function that will be invoked for each signature within one single loop through the collection of API calls.

* `on_complete`: After the loop through the collection of API calls is complete, it will be invoked to either trigger the detection or not.


```python
filter_apinames = ["NtCreateFile"]   # Filter API calls to only include NtCreateFile

def __init__(self):
    self.detect = False

def on_call(self, call, process):
    
    if call["api"] == "NtCreateFile":
        fileName = self.get_argument(call, "FileName")
        if "chrome" in fileName:
            self.mark_call(call)   # add a mark to the API call
            self.detect = True 

def on_complete(self):
    return self.detect
```

To detect it, we first need to understand what legitimate usage looks like. This means identifying the whitelisted processes (e.g., Chrome itself, system utilities) that are normally allowed to perform App-Bound decryption.

Once that baseline is established, detection becomes a matter of monitoring for a suspicious sequence of API calls. Rather than flagging a single function, it's more reliable to look for a behavioral pattern (Sequence).

In the case of Defendnot or similar payloads, the sequence usually involves three key steps:

* Reading Chrome's State file - This file contains the encrypted App-Bound key, typically located in the user's Chrome profile directory.

* Creating a COM object - Used to trigger Windows APIs that decrypt the App-Bound key, likely through DPAPI or protected storage interfaces.

* Saving the decrypted key - The decrypted key is written to disk, for example, in a file like `chromekey.txt` inside the `Recents` directory.


```python
from lib.cuckoo.common.abstracts import Signature

class ChromeStealer(Signature):
    name = "infostealer_chrome"
    description = "Glove-Stealer Payload App-Bound Key Decryption"
    severity = 3
    categories = ["infostealer"]
    authors = ["para0x0dise"]
    families = ["Glove-Stealer Payload"]
    evented = True
    ttps = ["T1555.003", "T1140", "T1552.001"]
    references = ["https://www.gendigital.com/blog/insights/research/glove-stealer"]

    filter_apinames = set(["NtReadFile", "NtWriteFile", "CoCreateInstance"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.sequence = 0
        self.fileHandles = set()
        self.safeIndicators = (
            "google\\chrome\\application\\chrome.exe",
            "bravesoftware\\brave-browser\\application\\brave.exe",
            "microsoft\\edge\\application\\msedge.exe",
            "vivaldi\\application\\vivaldi.exe",
            "opera\\opera.exe",
            "opera software\\opera gx stable\\opera.exe",
            "chromium\\application\\chromium.exe",
            "comodo\\dragon\\dragon.exe",
            "srware iron\\iron.exe",
            "torch\\torch.exe",
            "yandex\\yandexbrowser\\application\\browser.exe",
            "360browser\\browser\\360browser.exe",
            "maxthon\\application\\maxthon.exe",
            "centbrowser\\application\\centbrowser.exe",
            "slimjet\\slimjet.exe",
            "blisk\\blisk.exe",
            "epic privacy browser\\epic.exe"
        )
        self.clsids = [
            "708860E0-F641-4611-8895-7D867DD3675B",  # Chrome
            "1FCBE96C-1697-43AF-9140-2897C7C69767",  # Edge
            "576B31AF-6369-4B6B-8560-E4B203A97A8B",  # Brave
        ]
        self.riids = [
            "463ABECF-410D-407F-8AF5-0DF35A005CC8", # Chrome
            "C9C2B807-7731-4F34-81B7-44FF7779522B", # Edge
            "F396861E-0C8E-4C71-8256-2FAE6D759CE9", # Brave
        ]

    def on_call(self, call, process):
        if any(indicator in process["module_path"].lower() for indicator in self.safeIndicators):
            return False
        
        if call["api"] == "NtReadFile":
            fileName = self.get_argument(call, "HandleName")
            fileHandle = self.get_argument(call, "FileHandle")
            
            if ("\\Local\\Google\\Chrome\\User Data\\Local State" in fileName):
                if not fileHandle in self.fileHandles:  # Avoid duplicate calls (if ReadFile is called multiple times)
                    self.fileHandles.add(fileHandle)
                    self.mark_call()
                    self.sequence += 1  # Increment the sequence counter
        
        elif call["api"] == "CoCreateInstance":
            clsid = self.get_argument(call, "rclsid")
            riid = self.get_argument(call, "riid")

            if (clsid in self.clsids and riid in self.riids):
                    self.mark_call()
                    self.sequence += 1  # Increment the sequence counter

        elif call["api"] == "NtWriteFile":
            fileName = self.get_argument(call, "HandleName")
            if "chromekey.txt" in fileName:
                self.data.append({"file": process["module_path"]})
                self.mark_call()
                self.sequence += 1

    def on_complete(self):
        if self.sequence >= 2:  # Trigger detection if at least 2 API calls are detected
            return True
        return False
```

{% include my_figure.html src="/assets/images/Absurdities/Part-1/appBound_DetectionRule.png" caption="Figure 14: Trigger Glove Stealer Payload" %}



# Absurdity-II: Behind the Shield - Digging into Defendnot

In this post, I'm diving deep into the inner workings of the open-source tool ([Defendnot](https://github.com/es3n1n/defendnot)), which was released as an evolution of the now-removed [no-defender](https://github.com/es3n1n/no-defender). That earlier tool was taken down from GitHub via a **DMCA Takedown Notice** on June 8, 2024, likely due to its ability to disable Microsoft Defender.

Defendnot takes a more refined approach. Instead of killing Defender directly, it registers itself as a fake antivirus, abusing **Windows Security Center (WSC) APIs** to make Windows think another security product is already in place — which causes Microsoft Defender to step aside automatically.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/Summary_fakeAV.png" caption="Figure 15: Just Wild About Jerry" %}

Defendnot's Main Components:
* **defendnot.dll** - The core DLL responsible for faking an antivirus registration and disabling Defender via WSC APIs.
* **defendnot.exe** - A helper executable that injects defendnot.dll into a target (legitimate) process to carry out the bypass.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_Graph.png" caption="Figure 16: Defendnot Flow" %}

## defendnot.exe
defendnot.exe acts as the main loader — it's the entry point of the whole fake antivirus registration process by injecting defendnot.dll into a target process.

***<u>Step 1: Ensuring WSC is Running:</u>***
The first thing it does is call a function named `loader::ensure_environment()`. This function checks whether the Windows Security Center (WSC) service is active. It uses the Service Control Manager (SCM) via `OpenServiceW` to query the status of the service.

If WSC isn't running, it tries to start it manually using `StartServiceW`.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_WSCGetService.png" caption="Figure 17: defendnot.exe ensures Windows Security Center (WSC) service is running" %}

***<u>Step 2: Setting Up the Fake AV Context:</u>***
Next, it calls `setup_context()`, another function in the loader namespace. This one parses and loads configuration values passed through command-line arguments. These options define how the fake antivirus should behave:

* Name: What name should the fake AV provider register under?
* Flag: Should the fake AV be enabled or just registered?
* AutoRun Type: What privilege level should the fake AV run under? (CurrentUser or SYSTEM)
* AutoRun Flag (Optional): Should the fake AV persist by running at system startup?


{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_ConfigSetup.png" caption="Figure 18: Configuration Setup" %}

To be noted all necessary configurations are stored inside `strings` namespace 

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_storedConfigs.png" caption="Figure 19: Stored Configurations" %}

After setting up the environment and context, defendnot.exe moves on to execute load_defendnot(), which is responsible for injecting the main payload — defendnot.dll — into the Taskmgr.exe process. This is done using a helper function called loader::inject().

***<u>Step 3: Launching the Target Process:</u>***
The tool first creates the Taskmgr.exe process in a suspended state using `CreateProcessA` with the following flags:

* `CREATE_SUSPENDED`: Ensures the process is created but its primary thread doesn't run immediately.
* `DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS`: Makes the injector act as a debugger for Taskmgr.exe to overcome an issue when injecting the DLL to that process.

***<u>Step 4: Injecting the DLL via Remote Thread:</u>***

Once the process is suspended and under control:

* A block of memory is allocated in the target process using `VirtualAllocEx`.
* The path to defendnot.dll is written into that memory with `WriteProcessMemory`.
* A remote thread is created using `CreateRemoteThread`, with `LoadLibraryA` as the entry point and the DLL path as the argument.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_DLLInjection.png" caption="Figure 20: Injecting defendnot.dll into Taskmgr.exe" %}

Before attempting to inject the DLL into Taskmgr.exe, defendnot.exe establishes Inter-Process Communication (IPC) with it to coordinate and track the registration process.

This IPC channel is identified by the name: `defender-disabler-ipc`

The loader communicates with the injected DLL over this channel, sending commands and waiting for status updates until the fake antivirus registration is complete.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_CreateIPC.png" caption="Figure 21: IPC Setup" %}


It's worth noting that defendnot.dll isn't limited to being injected into Taskmgr.exe. The tool can inject into any executable located in System32 or SysWOW64, as long as the target file is verified and signed.

Before injecting the DLL, the tool performs a strict validation process on the target executable:

1. **<u>PE Header Check</u>**
It first ensures the file has valid `IMAGE_DOS_HEADER` and `IMAGE_NT_HEADERS`.

2. **<u>Force Integrity Flag</u>**
It checks whether the `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` flag is set. According to [Microsoft](https://learn.microsoft.com/en-us/cpp/build/reference/integritycheck-require-signature-check?view=msvc-170), this flag tells the memory manager to check for a digital signature in order to load the image in Windows.

3. **<u>Digital Signature Verification</u>**
It retrieves the digital signature of the file using `CryptQueryObject` function and then verifies the signature using `CryptMsgGetAndVerifySigner` function.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_CheckExecutable.png" caption="Figure 22: Defendnot verification process" %}

## defendnot.dll

Once injected, defendnot.dll starts its execution by spawning a new thread using `CreateThread`. This thread runs the bootstrapping startup routine, which is responsible for registering the DLL as a fake antivirus provider in Windows Security Center (WSC).

To achieve this, the code interacts with the `IWscAvStatus` COM interface, leveraging three methods:

* `com::query` - Retrieves the `WSC` COM interface.
* `Register` - Adds the fake antivirus provider entry to WSC, making it appear as a legitimate AV product.
* `UpdateStatus` - Updates the status of the fake provider to show that it's active. I believe that Windows Defender will be disabled once the fake AV is registered.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_AbuseWSCAPIs.png" caption="Figure 23: Defendnot.dll startup code" %}

## Juicy Lucy: Chasing the COM Trail
At this point, API hooking alone isn't enough to catch Defendnot's tricks — the malicious behavior is too well hidden. So, we need to go deeper and trace the actual sequence of API calls to understand what's really happening under the hood.

As shown earlier, Defendnot relies on the Windows Security Center (WSC) COM interface, which means it must use `CoCreateInstance` to instantiate WSC-related objects. Fortunately, es3n1n conveniently documented the CLSID and IIDs of the interfaces used.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_CLIDWSC.png" caption="Figure 24: CLSID and IIDs of each interface" %}


To start the investigation, fire up your debugger and attach it to the `Taskmgr.exe` process (the injected host). You can follow the excellent walkthrough from [Malware Analysis for Hedgehogs](https://youtu.be/W_rAxPm4TTU)

Once inside, you'll see that `CoCreateInstance` receives the WSC CLSID (in little-endian format) as the first argument — a clear sign it's about to spin up a COM object for WSC.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_CoCreateInstanceWSC_CLSID.png" caption="Figure 25: Creating WSC COM Object" %}

Digging further, you'll notice that execution flows into a DLL named `wscisvif.dll`, which internally relies on `wscapi.dll` — the real workhorse behind WSC operations. This DLL exposes key methods:
* `wscRegisterSecurityProduct` → Registers the fake antivirus
* `wscUnregisterSecurityProduct` → Removes the fake AV
* `wscUpdateProductStatus` → Activates the fake AV status

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_WSCInternalMethods.png" caption="Figure 26: WSC Internal Methods" %}

## Under the Hood: wscRegisterSecurityProduct
Lets dig deeper into the registration mechanism. The `wscRegisterSecurityProduct` function starts by setting up an RPC connection to the WSC service.

### RPC Connection Creation:
First, it creates a binding string using `RpcStringBindingComposeW`, which combines:

* UUID: `06BBA54A-BE05-49f9-B0A0-30F790261023` (WSC interface)
* Protocol sequence: `ncalrpc` (Local named pipes)

Then, it generates the actual RPC binding handle using `RpcBindingFromStringBindingW`.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_createBindingStringHandle.png" caption="Figure 27: create a string binding handle" %}

Then, it will execute the actual RPC calls with the WSC service using the handle already created and passes the AV provider info such as name, company, etc to the WSC service using undocumented function called `NdrClientCall3`.

### Triggering RPC Call:

Once the binding is ready, it performs the actual RPC call to the WSC service. It sends the fake AV's metadata — like product name, company, and version — using an undocumented function called `NdrClientCall3`.

As explained in [Kai Huang - Uncovering RPC Servers through Windows API Analysis](https://posts.specterops.io/uncovering-rpc-servers-through-windows-api-analysis-5d23c0459db6), `NdrClientCall3` is an internal function that is used to call the RPC server through our binding handle. It takes a `MIDL_STUBLESS_PROXY_INFO` structure, which contains a `MIDL_STUB_DESC` structure pointing to `RpcInterfaceInformation`.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_RPCInterfaceInfo.png" caption="Figure 28: RPC Interface Information" %}

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_rpcClinetInterfaceStruct.png" caption="Figure 29: RPC Client Interface Structure" %}

Now, it will pass 2 important arguments which I believe that they are the provider name and company name to register it.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_Provider_CompanyName.png" caption="Figure 30: Provider and Company Name to register" %}

To be noted, defendnot assigns multiple IIDs of WSC interface based on it's version, so as shown in that figure, it will register the fake AV using V4 interface.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_usingWSCV4.png" caption="Figure 31: WSC Interface Version" %}

## Detection Rule:
Due to an issue on CAPE sandbox, I will track used API calls using API-Monitor. As shown in the figure below, defendnot-loader uses a remote thread to inject the DLL into the target process (Taskmgr.exe) and then it will register itself using WSC COM interface.

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_APIMonitor-Loader.png" caption="Figure 32: Tracking API Calls" %}

{% include my_figure.html src="/assets/images/Absurdities/Part-1/defendnot_APIMonitor-COM.png" caption="Figure 33: Tracking API Calls" %}

To minimize false positives, it's important to exclude legitimate antivirus products that also interact with the same WSC COM interfaces and then start our detection by tracking the DLL injection sequence, focusing on the creation of a remote thread in a target process. Once that's established, we look for COM interface usage, particularly calls to `CoCreateInstance` using known CLSID and IID values associated with WSC.

```python
from lib.cuckoo.common.abstracts import Signature

class DefendNot(Signature):
    name = "antiav_defendnot"
    description = "DefendNot Anti-AV"
    severity = 3
    categories = ["antiav"]
    authors = ["para0x0dise"]
    families = ["DefendNot"]
    minimum = "0.5"
    ttps = ["T1562.001", "T1055.003"]
    references = [
        "https://www.huntress.com/blog/defendnot-detecting-malicious-security-product-bypass-techniques", 
        "https://github.com/es3n1n/defendnot"
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.sequence = 0
        self.isRegistered = False
        self.processHandles = set()
        self.processPids = set()
        self.handle2pid = dict()
        self.clsid = "F2102C37-90C3-450C-B30F-92BE1693BDF2"  # CLSID_WscIsv

        self.riids = (
            "9B8F6C6E-8A4A-4891-AF63-1A2F50924040",  # IID_IWscFWStatus
            "62F698CB-094A-4C68-9419-8E8C49420E59",  # IID_IWscFWStatus2
            "3901A765-AB91-4BA9-A553-5B8538DEB840",  # IID_IWscAVStatus
            "CF007CA2-F5E3-11E5-9CE9-5E5517507C66",  # IID_IWscAVStatus3
            "4DCBAFAC-29BA-46B1-80FC-B8BDE3C0AE4D",  # IID_IWscAVStatus4
            "024E9756-BA6C-4AD1-8321-87BAE78FD0E3",  # IID_IWscASStatus
        )
        # Dictionary of known AV installations: {path: [process_names]} - Optimized structure
        self.knownAVs = {
            # Microsoft Defender (Windows 10/11 modern paths)
            r'c:\programdata\microsoft\windows defender\platform': [
                'msmpeng.exe', 'mpcmdrun.exe', 'mpdefendercoreservice.exe', 
                'nissrv.exe', 'antimalwareservice.exe'
            ],
            r'c:\program files\windows defender': [
                'msmpeng.exe', 'mpcmdrun.exe', 'mpdlpservice.exe'
            ],
            
            # AVG Antivirus
            r'c:\program files\avg\antivirus': [
                'avgui.exe', 'avgsvca.exe', 'avgsvc.exe', 'avgnt.exe'
            ],
            r'c:\program files (x86)\avg\antivirus': [
                'avgui.exe', 'avgsvca.exe', 'avgsvc.exe', 'avgnt.exe'
            ],
      
            # McAfee/Trellix Antivirus
            r'c:\program files\mcafee\common framework': [
                'mfevtps.exe', 'mfeann.exe', 'mcafeeservice.exe', 'mctray.exe'
            ],
            r'c:\program files\mcafee\endpoint security': ['mfeesp.exe'],
            r'c:\program files\mcafee': ['mcuicnt.exe'],
            
            # Kaspersky Antivirus
            r'c:\program files\kaspersky lab\kaspersky anti-virus': ['avp.exe'],
            r'c:\program files (x86)\kaspersky lab\kaspersky anti-virus': ['avp.exe'],
            r'c:\program files\kaspersky lab\kaspersky internet security': ['avp.exe'],
            r'c:\program files (x86)\kaspersky lab\kaspersky internet security': ['avp.exe'],
            r'c:\program files\kaspersky lab\kaspersky total security': ['avp.exe'],
            r'c:\program files\kaspersky lab': [
                'klnagent.exe', 'avpui.exe', 'kavfsmui.exe'
            ],
            r'c:\program files (x86)\kaspersky lab': [
                'klnagent.exe', 'avpui.exe', 'kavfsmui.exe'
            ],
            
            # Malwarebytes
            r'c:\program files\malwarebytes\anti-malware': [
                'mbam.exe', 'mbamservice.exe', 'mbamgui.exe', 'mbamdor.exe'
            ],
            r'c:\program files (x86)\malwarebytes\anti-malware': [
                'mbam.exe', 'mbamservice.exe', 'mbamgui.exe', 'mbamdor.exe'
            ],
            
            # Bitdefender Antivirus
            r'c:\program files\bitdefender': [
                'vsserv.exe', 'bdagent.exe', 'updatesrv.exe', 'bdwtxag.exe', 'productdata.exe'
            ],
            
            # ESET Antivirus
            r'c:\program files\eset': [
                'ekrn.exe', 'egui.exe', 'ecmd.exe', 'eamsi.exe', 'eguiproxy.exe'
            ],
        }

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        pPath = process["module_path"].lower()

        for avPath, avProcesses in self.knownAVs.items():
            if avPath.lower() in pPath and pname in avProcesses:
                return False

        if call["api"] == "CreateProcessInternalW" and call["status"] and self.sequence == 0:
            flags = self.get_argument(call, "CreationFlags")

            # Check for CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS flags
            if flags & 0x4 or flags & 0x7: 
                self.processHandles.add(self.get_argument(call, "ProcessHandle"))
                self.handle2pid[self.get_argument(call, "ProcessHandle")] = self.get_argument(call, "ProcessId")
                self.sequence += 1
                self.mark_call()

        # Check Buffer Allocation for DLL
        elif (call["api"] == "VirtualAllocEx" or call["api"] == "NtAllocateVirtualMemory") and self.sequence == 1:
            processHandle = self.get_argument(call, "ProcessHandle")
            if processHandle in self.processHandles:
                self.sequence += 1
                self.mark_call()

        # Check for DLL Write
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "WriteProcessMemory") and self.sequence == 2:
            processHandle = self.get_argument(call, "ProcessHandle")
            buf = self.get_argument(call, "Buffer")
            if processHandle in self.processHandles:
                if buf.endswith(b".dll"):
                    self.sequence += 1
                    self.mark_call()

        # Check for Remote Thread Creation
        elif (call["api"] == "CreateRemoteThread" or call["api"].startswith("NtCreateThread")) and self.sequence == 3:
            handle = self.get_argument(call, "ProcessHandle")
            if handle in self.processHandles:
                self.sequence += 1
                self.mark_call()

        # Check for CoCreateInstance
        elif call["api"] == "CoCreateInstance" and self.sequence >= 2:
            clsid = self.get_argument(call, "rclsid")
            riid = self.get_argument(call, "riid")

            if clsid == self.clsid and riid in self.riids: 
                self.isRegistered = True
                self.mark_call()

    def on_complete(self):
        if self.sequence >= 2 and self.isRegistered:
            return True
        return False
```

# References
[Katz and Mouse Game](https://www.elastic.co/security-labs/katz-and-mouse-game)

[The Curious Case of the Cantankerous COM Decrypting Microsoft Edge ABE](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/blob/719c1d3507e6cb8135111c6b83927e375724bdec/docs/The_Curious_Case_of_the_Cantankerous_COM_Decrypting_Microsoft_Edge_ABE.md)

[Glove Stealer](https://www.gendigital.com/blog/insights/research/glove-stealer)

[Snake Infostealer Malware](https://www.cybereason.com/blog/research/threat-analysis-report-snake-infostealer-malware)

[Defendnot Detecting Malicious Security Product Bypass Techniques](https://www.huntress.com/blog/defendnot-detecting-malicious-security-product-bypass-techniques)

[Uncovering RPC Servers through Windows API Analysis](https://posts.specterops.io/uncovering-rpc-servers-through-windows-api-analysis-5d23c0459db6)

[Malware Analysis for Hedgehogs](https://youtu.be/W_rAxPm4TTU)
