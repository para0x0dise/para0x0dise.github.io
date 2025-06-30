---
title: "forn00bies Level-2"
layout: single
date: 2020-10-27 15:40:40 +0200
description: "The objective is to get a valid password from User Id."
toc: true
toc_label: "Table of contents"
header:
    teaser: /assets/images/Reverse-Engineering/forn00bies/0.png
ribbon: blue

categories: 
    - CrackMes
---
You can get Challenges [here](https://github.com/jojo-0x00/CrackMEs)
## Summary
>* Getting the CPU Timestamp (Number of clock cycles from the last reset). See more [here](https://en.wikipedia.org/wiki/Time_Stamp_Counter)
>* Making some tests on this Timestamp and modify this value.
>* Generating the final password from these modifications.

## Code Analysis
First, it initializes a buffer (user_id) and fills it of 32-byte of 0x4F (O character) 

[![1](/assets/images/Reverse-Engineering/forn00bies/first.png)](/assets/images/Reverse-Engineering/forn00bies/first.png)

 Then, it generates CPU Timestamp by `RDTSC`(Read Time-Stamp Counter) instruction at offset `00401401` and prints it out as User Id and moves this buffer into edi at offset `00401413`.&nbsp; <font size="3">See more</font> [rdtsc](https://www.aldeid.com/wiki/X86-assembly/Instructions/rdtsc)

[![2](/assets/images/Reverse-Engineering/forn00bies/second.png)](/assets/images/Reverse-Engineering/forn00bies/second.png)


Now, there are some tests that the Time-Stamp Counter pass through first:
1. Bit_Test.
2. Comparison between Time-Stamp Counter and 0xB16B00B5.
3. Parity Test.
 
### Bit_Test
It uses `BT` instruction to make a bit test at offset `00401418` and there is `JNB` (jump to `zero_bit_set` if CF == 0).&nbsp; <font size="3">See more</font> [bt](https://www.aldeid.com/wiki/X86-assembly/Instructions/bt)
<br />
<br />
if not, it will replace the first byte of buffer with 0x2A (* symbol) and go to offset `00401421`
 
 [![3](/assets/images/Reverse-Engineering/forn00bies/third.png)](/assets/images/Reverse-Engineering/forn00bies/third.png)

### if (Time-Stamp > 0xB16B00B5)
Now, it increases `EDI` offset to be `0040D021`. Then, it makes a comparison between Time-Stamp and 0xB16B00B5 (jump to `above_b16b00b5h` if above)
<br />
<br />
if not, it will replace the second byte of buffer with 0x2A (* symbol) and go to offset `0040142D`

 [![4](/assets/images/Reverse-Engineering/forn00bies/forth.png)](/assets/images/Reverse-Engineering/forn00bies/forth.png)

### Parity Test
Last but not least, It increased the `EDI` by 1 and there is `JNP` (jump to `no_parity` if PE == 0). This jump will be never taken because PE is always set.

when `EDI` is increased, it will be `0040D022`<br />(`1000000 11010000 00100010` in binary) the least significant byte has an even number of 1's so this jump is never taken. 

Then it will replace the third byte of buffer with 0x2A (* symbol) and go to offset `00401433` 

 [![5](/assets/images/Reverse-Engineering/forn00bies/fifth.png)](/assets/images/Reverse-Engineering/forn00bies/fifth.png)

### 28-loop
Finally, it will make the last modifications to the buffer. It makes a loop 28 times, sets `ECX` as a counter, and initializes it with 0x1C (28). It makes the following:
1. Shift-Right the Time-Stamp Counter by 1.
2. Divide the result by 0x1A and put the remainder into `EDX`.
3. Make a bitwise-AND operation with 1 and jump to offset `0040145E` if zero and add the next byte of buffer with 0x61.
4. Else it will continue to offset `00401454` and add the next byte of buffer with 0x41.
5. Finally, set `EDX` to zero.

 [![6](/assets/images/Reverse-Engineering/forn00bies/sixth.png)](/assets/images/Reverse-Engineering/forn00bies/sixth.png)

As shown in this flowchart:

 [![7](/assets/images/Reverse-Engineering/forn00bies/seventh.png)](/assets/images/Reverse-Engineering/forn00bies/seventh.png)

## Boo0M
 [![8](/assets/images/Reverse-Engineering/forn00bies/eighth.png)](/assets/images/Reverse-Engineering/forn00bies/eighth.png)

## Keygen
[Github](https://github.com/jojo0x00/Reverse-Engineering-Challenges/tree/master/CrackMe/forn00bies)
