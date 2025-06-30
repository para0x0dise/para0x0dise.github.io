---
title: "PowerGrid Crisis"
layout: single
date: 2021-05-16
description: "The city has been without main power for 3 days now. It's critical for heat & light.<br> Mission: Turn on the power generators to bring the PowerGrid online."
toc: true
toc_label: "Table of contents"
header:
    teaser: /assets/images/Reverse-Engineering/PowerGrid/background.png
ribbon: blue

categories: 
    - CrackMes
---
You can get this challenge [here](https://crackmes.one/crackme/609ab82a33c5d4544d40d5b2)
## Summary
>* This challenge is based on the value of the `CF` flag.
>* Reboot.
>* Enter EMERGENCY MODE (simple XOR).
>* Reboot.

## Tricky Password
First, it asks for a password. 

[![1](/assets/images/Reverse-Engineering/PowerGrid/1.png)](/assets/images/Reverse-Engineering/PowerGrid/1.png)

I tried to find it out but I realized it's just a trick. It doesn't matter because the password will be always wrong. 

It compares the input with itself until `ECX` is equal to 0. Then it goes to (WRONG PASSWORD)

[![2](/assets/images/Reverse-Engineering/PowerGrid/2.png)](/assets/images/Reverse-Engineering/PowerGrid/2.png)

## Welcome GUEST

Now, We have this window with these functions. It's required to turn on the (POWER GENERATORS) to reactivate the POWERGRID so let's try `Toggle power Generators`

[![3](/assets/images/Reverse-Engineering/PowerGrid/3.png)](/assets/images/Reverse-Engineering/PowerGrid/3.png)

Oops! It's not responding. It's time for Reversing.

[![4](/assets/images/Reverse-Engineering/PowerGrid/4.png)](/assets/images/Reverse-Engineering/PowerGrid/4.png)

At `0x4016CF` we have a function that contains a switch case. These are the available control modules of POWERGRID.

[![5](/assets/images/Reverse-Engineering/PowerGrid/5.png)](/assets/images/Reverse-Engineering/PowerGrid/5.png)

Let's dig inside `Toggle_power_Generators`

### Toggle Power Generators

I don't want the red area so I have to set the `CF` flag. 

Here I see `RCL` and `RCR`, they are like `SHR` and `SHL` but they include the CF flag in the shifting 

[![6](/assets/images/Reverse-Engineering/PowerGrid/6.png)](/assets/images/Reverse-Engineering/PowerGrid/6.png)


[![RCL](/assets/images/Reverse-Engineering/PowerGrid/RCL.png)](/assets/images/Reverse-Engineering/PowerGrid/RCL.png)

[![RCR](/assets/images/Reverse-Engineering/PowerGrid/RCR.png)](/assets/images/Reverse-Engineering/PowerGrid/RCR.png)

the condition variable is `ZERO`. This value is moved into `AL` and it makes `RCL` with 1 so I need to set suitable 1's to set the `CF` flag and get into the green area.

As shown, these are the valid 1's that make the `CF` flag always set.

[![7](/assets/images/Reverse-Engineering/PowerGrid/7.png)](/assets/images/Reverse-Engineering/PowerGrid/7.png)

[![8](/assets/images/Reverse-Engineering/PowerGrid/8.png)](/assets/images/Reverse-Engineering/PowerGrid/8.png)

How to set these one(s)? This variable is OR-ed with `0x80`, `0x40`, `0x1` at these functions: 
1. Reboot 
2. Check_Privileges 

So we need these operations to get the valid one(s) and turn on the POWER GENERATORS.

[![9](/assets/images/Reverse-Engineering/PowerGrid/9.png)](/assets/images/Reverse-Engineering/PowerGrid/9.png)

```
0x80 ==> 10000000
0x40 ==> 01000000
0x1  ==> 00000001

Final Sequence: 11000001
```

### Reboot

Inside this function, there is an `RCL` operation with 1 but the condition variable still not set so the (CF == 0)

There is a `JB` (This jump is taken when CF == 1) but the false direction will be taken and the condition variable will be OR-ed with `0x80`  

[![10](/assets/images/Reverse-Engineering/PowerGrid/10.png)](/assets/images/Reverse-Engineering/PowerGrid/10.png)

I can see also another OR operation with `0x40` but there is `RCR` with 1 and the jump will not be taken because the first bit of the condition variable is not set. 

[![11](/assets/images/Reverse-Engineering/PowerGrid/11.png)](/assets/images/Reverse-Engineering/PowerGrid/11.png)


### Check Privileges 

After getting the first one from the `Reboot` function, we can get into `Check_Privileges` for OR operation with `0x1`.

Here, there is `RCL` with 1 and `RCR` with 1, the jump will be taken in both cases.

[![12](/assets/images/Reverse-Engineering/PowerGrid/12.png)](/assets/images/Reverse-Engineering/PowerGrid/12.png) | [![13](/assets/images/Reverse-Engineering/PowerGrid/13.png)](/assets/images/Reverse-Engineering/PowerGrid/13.png)

It asks for my smart card but I don't have it. I only have to make some reversing to get the `EMERGENCY SECRET CODE`.

It's very easy it's just a basic `XOR` operation.

> The idea of this operation is to make `ECX` equal to zero; This will be useful to bypass this condition and get the OR operation
[![15](/assets/images/Reverse-Engineering/PowerGrid/15.png)](/assets/images/Reverse-Engineering/PowerGrid/15.png)


Before using our debugger, there is an Anti-Debugging Check we have to defeat. 

At `0x40161D`, there is a call to `IsDebuggerPresent` which checks the `BeingDebugged` Flag inside the `PEB` structure.

[![16](/assets/images/Reverse-Engineering/PowerGrid/16.png)](/assets/images/Reverse-Engineering/PowerGrid/16.png)


> This flag is set if the debugger is used so we have to reset it to ZERO.

Let's debugging now.

Here I see a wired string `'/+=)8iig`, in which each character is moved to `AL` based on the inverted value of CODE LENGTH.

> To make it start from the beginning of this string, the code length should be 9.

[![17](/assets/images/Reverse-Engineering/PowerGrid/17.png)](/assets/images/Reverse-Engineering/PowerGrid/17.png)

Now, It XORs each character with a key starting from `0x57` to `0x5f`. 

With these pieces, I can generate the `EMERGENCY SECRET CODE`.

```python
encryptedCode = "'/+=)8iig"
key = [0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f]

for index, keyElement in enumerate(key):
    print(chr(keyElement ^ ord(encryptedCode[index])), end='')

output: pwrgrd478
```

Now, Emergency Mode is Activated.

[![18](/assets/images/Reverse-Engineering/PowerGrid/18.png)](/assets/images/Reverse-Engineering/PowerGrid/18.png)


### Reboot Again

The condition variable is `10000001`, we can bypass the `RCR` operation and get the 3rd OR with `0x40`

[![19](/assets/images/Reverse-Engineering/PowerGrid/19.png)](/assets/images/Reverse-Engineering/PowerGrid/19.png)

[![20](/assets/images/Reverse-Engineering/PowerGrid/20.png)](/assets/images/Reverse-Engineering/PowerGrid/20.png)


## Crisis Solved

Generators are on. Power Grid is reactivated

[![21](/assets/images/Reverse-Engineering/PowerGrid/Final.gif)](/assets/images/Reverse-Engineering/PowerGrid/Final.gif)
