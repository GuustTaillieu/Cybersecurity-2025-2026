# Lab 1 - Emulator - ADB - ROOT

## Emulator
The Android emulator is a part of the Android Studio environment. https://developer.android.com/studio

Follow this tutorial for installation: https://developer.android.com/studio/install and create an AVD (Android Virtual Device): https://developer.android.com/studio/run/managing-avds#createavd.
The AVD needs to have the following requirements:
- Without PlayStore
- API36
- GoogleAPI ROM

## ADB
Install ADB on your host machine using the SDK tools (https://developer.android.com/tools/adb).

### ADB commands
Answer the following questions using ADB commands:
- List all devices using ADB
- Show the battery status of the emulator
- Copy a .txt file to the device, edit this file in the shell and copy back to the host.
- Create a screenshot with adb and store it on the host.
- Open the Google search bar and search from adb.
- List all running processes on the Android device.
- List all installed apps on the Android device.

## Root the emulator
Root the created AVD and check with the app `rootchecker` (apk available on Leho) if root was successful.

## Magisk modules
- Enable `Zygisk`
- Install App Systemizer (Terminal Emulator)
- Install other modules you seem useful in Magisk

## Android security
- Install the apk found on LEHO via ADB.
- Start the apk via ADB  
*Note: find the package name first using `pm` - the default activity is koenk.lab1mobilesecurity.MainActivity*
*Note: first set adb in root mode.*
- Start the apk and find 4 keys in the application.  
- Bypass the code screen of the app (is the 4th key)