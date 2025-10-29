console.log("JavaScript loaded successfully ");

setTimeout(() => {
  Java.perform(() => {
    console.log("Starting implementation override.");
    const MainViewModel = Java.use("com.koenk.mobilesecuritylab5.MainViewModel");
    MainViewModel.controlPassword.implementation = function(passwd) {
      console.log("Key: " + this.getKey3());
      return false;
    }
  });
}, 0);
