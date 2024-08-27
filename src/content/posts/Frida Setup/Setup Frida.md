---
title: Setting up Frida for dynamic instrumentation of apps 
published: 2024-04-01
description: "Easy setup of Frida"
image: "./Frida.png"
tags: ["Android", "Reverse Engineering", "CTF"]
category: Guides
draft: false
---


Frida is **a dynamic binary instrumentation toolkit that allows us to execute scripts in previously locked down software**. It is very much necessary for android challenges as it even allows us to write our own implementation of any function and run.

# Installing Frida
We need to install frida on both our android device and our pc.
### Installing on android device
First we need to check our android device architecture. **Make sure that the device is connected to your system through USB(USB debugging should be on) or emulator is online**
Type the following command in your terminal to know the architecture of your device:
```
adb shell getprop ro.product.cpu.abi
```
This command retrieves the value of the `ro.product.cpu.abi` property, which indicates the CPU architecture of the device. The result will be one of the following values:
- `arm`
- `arm64`
- `x86`
- `x86_64`
Now to go to  https://github.com/frida/frida/releases and download the specific **android** release for your architecture.

Unzip the file and in the terminal go to the directory where you have the `frida-server`  file.
Now we need to push the `frida-server` on our device in a particular folder.
Type the command:
```
adb push frida-server-16.1.10-android-x86 /data/local/tmp/frida-server   
```
**Please change the file `frida-server-16.1.10-android-x86` according to the one you downloaded.**

Now type `adb shell` and then `cd /data/local/tmp`.
Then give executing permissions to the `frida-server` by typing 
`chmod 700 frida-server`

Run the frida-server by `./frida-server`

Now we are ready to inject Frida scripts into application process.