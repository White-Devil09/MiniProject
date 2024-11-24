Java.perform(function () {
    // Hook into the BroadcastReceiver onReceive method
    console.log("script started .....");
    const SmsReceiver = Java.use("android.content.BroadcastReceiver");
    SmsReceiver.onReceive.overload('android.content.Context', 'android.content.Intent').implementation = function (context, intent) {
        console.log("onReceive called for BroadcastReceiver");
        console.log("Intent Action: " + intent.getAction());
        
        const bundle = intent.getExtras();
        if (bundle != null) {
            const pdus = bundle.get('pdus');
            if (pdus) {
                for (var i = 0; i < pdus.length; i++) {
                    var format = intent.getStringExtra("format");
                    var sms = Java.use("android.telephony.SmsMessage").createFromPdu(pdus[i], format);
                    var sender = sms.getOriginatingAddress();
                    var body = sms.getMessageBody();
                    console.log("SMS from: " + sender + " Content: " + body);
                }
            }
        }
        this.onReceive(context, intent);  // Call the original onReceive method
    };
});
