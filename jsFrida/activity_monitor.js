Java.perform(function () {
    var Activity = Java.use("android.app.Activity");

    Activity.onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState) {
        var activityName = this.getClass().getName();
        console.log("Activity created: " + activityName);
        this.onCreate(savedInstanceState);
    };
});
