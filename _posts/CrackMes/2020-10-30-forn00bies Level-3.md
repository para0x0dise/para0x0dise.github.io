---
title: "forn00bies Level-3"
layout: single
date: 2020-10-30
description: "This challenge is based on trying and trying to get a valid guess."
toc: true
toc_label: "Table of contents"
header:
    teaser: /assets/images/Reverse-Engineering/forn00bies/Level-3/0.png
ribbon: blue

categories: 
    - CrackMes
---
You can get Challenges [here](https://github.com/jojo-0x00/CrackMEs)
## Summary
>* This challenge is based on trying and trying to get a valid guess.
>* It makes some tests to modify EFLAGS.
>* "BAD BOY" or "GOOD BOY" depends on the value of EFLAGS.


## Remember Some Basics
### EFLAGS
Before we get to the code analysis, we must remember some basics of EFLAGS.
<br />
EFLAGS is a 32-bit register that contains the current state of the processor.

[![1](/assets/images/Reverse-Engineering/forn00bies/Level-3/1.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/1.png)

CF: Set if the arithmetic operation generates carry or borrow out of the most significant bit of the result.

PF: Set if the most significant BYTE has an even number of 1's.

OF: Set if the arithmetic operation generates a large positive number or too small negative number. It's used also if we add 2 positive numbers and the sign bit exists.

ZF: Set if the arithmetic operation generates a ZERO.

* OF flag:

It's set when the value is out of range [-2^n to 2^n - 1]. Where n: number of bits.

i.e: If we add 2 positive numbers and the result is out of this range [-128 to +127] (also it's called signed number), the OF flag is set

[![0](/assets/images/Reverse-Engineering/forn00bies/Level-3/of.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/of.png)

* CF flag:

If we make an operation and there is a carry out in the result, the CF is set

[![0](/assets/images/Reverse-Engineering/forn00bies/Level-3/cf.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/cf.png)


## Code Analysis
It asks to enter a decimal number and saves it at `40D020`.

Then, it makes some tests on this input to modify EFLAGS and makes a jump to "BAD BOY" or not according to the CF flag.

[![2](/assets/images/Reverse-Engineering/forn00bies/Level-3/2.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/2.png)

It makes the following tests:
1. Parity Test (PF must be 1)
2. Guess Test (CF must be 0)
3. Zero Test (ZF must be 0)
4. Carry Test (CF must be 1)
5. Overflow Test (OF must be 1)
6. Zero Test again (ZF must be 1)

### Parity Test
It moves the input to `EAX` at `40141E` to make the first test.

First, at offset `401423` the XOR instruction is used to update the PF flag. Second, at offset `401426`, it uses `PUSHF` to push 16-bit of EFLAGS register and pops this value into `EBX`. Then, It makes Bit Test at offset `401428` to move PF bit to CF flag. 
```c
CF = PF = EFLAGS[2] 
```
>BT(bit test): it selects a bit at a specific offset (second operand) and stores it into the CF flag.


To continue, the PF must be set.

[![3](/assets/images/Reverse-Engineering/forn00bies/Level-3/3.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/3.png)

### Guess Test
At offset `40142E`, it makes a Bit Test to move the bit number 30 of the input to the CF flag. Then, It makes another Bit Test at offset `401434` to move the guessed bit to the CF flag. 
```c
CF = input[30] 
```

To continue, the guess bit must be 0.

[![4](/assets/images/Reverse-Engineering/forn00bies/Level-3/4.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/4.png)

### Zero Test
At offset `40143A`, it makes a bitwise AND operation with 1 (Test instruction) to update the ZF flag so the first bit of input must be set. Then, It makes Bit Test at offset `401441` to move ZF bit to CF flag. 
```c
CF = ZF = EFLAGS[6]
```

To continue, the ZF bit must be 0.

[![5](/assets/images/Reverse-Engineering/forn00bies/Level-3/5.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/5.png)

### Carry Test
At offset `401447`, it makes Shift-Left operation by 1 bit (shift the last bit of input to CF). Then, It makes Bit Test at offset `40144B` to move shifted bit to CF flag. 
```c
CF = input[31]
```

To continue, the shift bit must be 1 so the last bit of the input must be set.

[![6](/assets/images/Reverse-Engineering/forn00bies/Level-3/6.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/6.png)

### Overflow Test
At offset `401451`, it adds `0x60000000` to the previous result (After Shifting). Then, It makes Bit Test at offset `401458` to move OF bit to CF flag. 
```c
CF = OF = EFLAGS[11]
```
[![7](/assets/images/Reverse-Engineering/forn00bies/Level-3/7.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/7.png)

To continue, the OF bit must be 1 so how we do this:

`0x60000000` is `0110 0000 0000 0000 0000 0000 0000 0000` in binary we can make an OverFlow if we set the bit number 29 of input, shift the input and add to `0x60000000`, OF is set.
```c
input[29] = 1
```
[![0](/assets/images/Reverse-Engineering/forn00bies/Level-3/more1.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/more1.png)


### Zero Test again
At offset `401463`, it makes bitwise AND operation with `0x70000` (it's `0000 0000 0000 0111 0000 0000 0000 0000`in binary).

As seen, from 16th to 18th is set to 1 so if the input (after shifting and adding) has 1's at this area, the result is 1 (ZF = 0) and it will jump to "BAD BOY"

We must avoid adding 1's at this area of input to continue.

[![8](/assets/images/Reverse-Engineering/forn00bies/Level-3/8.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/8.png)

## Final check (loop into the input)
At offset `401470`, it moves the input to `EAX` and set `EDX` as a counter at offset `40147F`. It makes a Bit Test at a position of `EDX` and if CF is set, `EBX` is incremented by 1 at offset `401489`

After finishing the loop, the input (Starting from 2nd BYTE) is stored into `EAX` at offset `40148D`. Then, It makes XOR operation between `al` and `bl`.
>in other words, it compares between the number of 1's inside the input and the number that the 2nd BYTE of the input contains.

To get "GOOD BOY", they must be equal.

[![9](/assets/images/Reverse-Engineering/forn00bies/Level-3/9.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/9.png)

## Conclusion
[![0](/assets/images/Reverse-Engineering/forn00bies/Level-3/more2.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/more2.png)

[![10](/assets/images/Reverse-Engineering/forn00bies/Level-3/10.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/10.png)

## Boo0M
[![11](/assets/images/Reverse-Engineering/forn00bies/Level-3/11.png)](/assets/images/Reverse-Engineering/forn00bies/Level-3/11.png)

