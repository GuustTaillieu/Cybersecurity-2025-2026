console.log("JavaScript loaded successfully ");

setTimeout(() => {
  Java.perform(() => {
    console.log("Starting implementation override.");
    const MainViewModel = Java.use("com.koenk.mobilesecuritylab5.MainViewModel");
    const MainUIKt = Java.use("com.koenk.mobilesecuritylab5.MainUIKt");
    MainViewModel.getUsers.implementation = function(user, context) {
      MainUIKt.startActivity(context, 5, "3")
    }
  });
}, 0);
