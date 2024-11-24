Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("amazon")) {
                if(className.includes("otp") || className.includes("message") || className.includes("sms")){
                    console.log("Found class: " + className);
                }
            }
        },
        onComplete: function() {
            console.log("Enumeration complete");
        }
    });
});
