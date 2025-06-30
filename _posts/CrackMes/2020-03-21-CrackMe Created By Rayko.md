---
title: "CrackMe Created By Rayko"
layout: single
date: 2020-03-21 15:40:40 +0200
description: "The objective of this (.net) challenge is to crack the algorithm, generate a valid password and make a simple keygen."
toc: true
toc_label: "Table of contents"
header:
    teaser: /assets/images/Reverse-Engineering/Rayko/1.png
ribbon: blue

categories: 
    - CrackMes
---
## Objective

The objective of this (.net) challenge is to crack the algorithm, generate a valid password and make a simple keygen. 

[![1](/assets/images/Reverse-Engineering/Rayko/1.png)](/assets/images/Reverse-Engineering/Rayko/1.png)

## De-compiling
Let's use dnSpy to decompile the program. Now we are looking for **btnCheck_Click()**:

```c#
private void btnCheck_Click(object sender, EventArgs e)
{
 string input = Strings.Trim(this.txtName.Text);
 string right = Conversions.ToString(this.Encrypt(input));
 string left = Strings.Trim(this.txtSerial.Text);
 bool flag = Operators.CompareString(left, right, false) == 0;
 if (flag)
 {
    Interaction.MsgBox("You Put In The Right Serial Number", MsgBoxStyle.OkOnly, null);
 }
 else
 {
    Interaction.MsgBox("Try Again", MsgBoxStyle.OkOnly, null);
 }
}
```
### Encryption Function
We found that the name is encrypted using **Encrypt(input)**. 
>Now let's dig into this function:

```c#
private int Encrypt(string Input)
{
    int num = 0;
    checked {

    int num2 = Input.Length - 1;
    int num3 = num;
    int num6;
    for (;;) {

      int num4 = num3;
      int num5 = num2;
      if (num4 > num5){
        break;
      }
      char @string = Conversions.ToChar(Input.Substring(num3));
      num6 = (int)Math.Round(unchecked(Conversions.ToDouble(Conversion.Oct(Strings.Asc(Conversions.ToString(num6))) + Conversion.Oct(Strings.Asc(@string))) + 666.0));
      num3++;
    }

      return num6;
  } 
}
```
There are too many conversions. Let's divide this algorithm into 2 parts:
#### First part

```c#
num6 = 0
Conversion.Oct(Strings.Asc(Conversions.ToString(num6)))
 = Conversion.Oct(Strings.Asc(Conversions.ToString(0)))
 = Conversion.Oct(Strings.Asc("0"))
 = Conversion.Oct(48) = "60"
```
1) Num6 = 0 in decimal and we will convert it to string so  
`Note:` 
```c#
Conversions.ToString()      //only converts the first digit
``` 
<br />
2) Num6 = ‘0’ the ascii code of it is (48)

3) Convert it to octal ==> oct(48) = 60                                   
`Note:` 
```c#
Conversion.Oct()    //Returns a string representing the octal value of a number.
``` 
<br />
4) So, the first part of serial is : "60"
<br />
<br />
<br />

#### Second part 
(i.e:name = "A")

```c#
Conversion.Oct(Strings.Asc(@string)) 
 = Conversion.Oct(Strings.Asc('A')) 
 = Conversion.Oct(65) 
 = "101"
 ```

1)@string = ‘A’ and we will convert it to ASCII Ascii code is (65)

2)We convert it to octal oct(65) = "101"
<br />
<br />
<br />
>* Finally: (put them together)

```c#
Conversions.ToDouble("60"+ "101") + 666 
 = Conversions.ToDouble( "60101") + 666 
 = 60101 + 666 
 = 60767            //Valid password
```

## Boo0M
The password is: 60767

[![1](/assets/images/Reverse-Engineering/Rayko/2.png)](/assets/images/Reverse-Engineering/Rayko/2.png)

## Keygen
Written in Python
{% highlight python linenos %}
name = str(input("Enter name:"))
num6 = '0'

for i in range(0, len(name)):
    #First part
    num6 = str(oct(ord(str(num6[0]))))    #string ==> ascii ==> octal ==>string
    
    #Second part
    strr = str(oct(ord(name[i])))         #ascii ==> octal ==> string
    password = int(num6[2:] + strr[2:]) + 666

    #Generating password
    num6 = str(password)

print(password)
{% endhighlight %}