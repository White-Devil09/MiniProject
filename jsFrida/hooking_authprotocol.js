
Java.perform(function() {
    var AuthPortalUIActivity = Java.use('com.amazon.identity.auth.device.AuthPortalUIActivity');

    // Hooking the unregisterReceiver method
    AuthPortalUIActivity.unregisterReceiver.overload('android.content.BroadcastReceiver').implementation = function(receiver) {
        console.log("unregisterReceiver called with receiver: " + receiver);

        // Call the original method
        this.unregisterReceiver(receiver);
    };
});
