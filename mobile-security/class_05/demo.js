/*
Step 1: get name application -> `frida-ps -Ua`
Step 2: get functions -> `frida-trace -U -j '*koenk*!*' -p 2957` -> notice: MainViewModel.checkCode: Loaded handler at "/home/koenk/__handlers__/com.koenk.fridademo.ui.theme.MainViewModel/checkCode.js"
Step 3: get specific function frida-trace -U -j '*koenk*!*check*' -p 12114
Step 4: click on button notice: 
    20097 ms  MainActivityKt.checkCode("<instance: com.koenk.fridademo.MainViewModel>", "<instance: android.content.Context, $className: com.koenk.fridademo.MainActivity>", "234R")
    20104 ms     | MainViewModel.checkCode("234R")
    20104 ms     | <= false
          
We need to overwrite checkCode() that returns true
*/

console.log("JavaScript loaded successfully ");

setTimeout(() => {
    Java.perform(() => {
        console.log("Starting implementation override.");
        try {
            var MainViewModel = Java.use("com.koenk.fridademo.MainViewModel"); 
        } catch (e) {
            console.error('Exception caught:', e.message);
        }
        
        MainViewModel.checkSecret.implementation = function(code){
            console.log("Check bypassed!")
            return true;
        }
    });
  }, 0);