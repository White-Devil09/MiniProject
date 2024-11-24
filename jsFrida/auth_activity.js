Java.perform(function() {
    var AuthPortalUIActivity = Java.use('com.amazon.identity.auth.device.AuthPortalUIActivity');

    console.log("Methods in AuthPortalUIActivity:");
    AuthPortalUIActivity.class.getMethods().forEach(function(method) {
        console.log(method);
    });
});
