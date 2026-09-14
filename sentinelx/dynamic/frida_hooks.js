/*
 * SENTINEL-X runtime instrumentation.
 *
 * Hooks the Android framework methods that matter for banking fraud and reports
 * each hit back to the Python side as a JSON message. Hooking at the framework
 * level is what defeats the sample's own concealment: reflection, string
 * decryption and packing all have to resolve to these same APIs to do anything,
 * and network calls are observed before TLS, so certificate pinning does not
 * hide the C2 URL.
 *
 * Every hook calls through to the original implementation - the goal is to watch
 * the sample, not to change what it does.
 */
'use strict';

var seen = {};

function report(kind, klass, method, args) {
    var key = kind + '|' + klass + '|' + method + '|' + (args || '');
    if (seen[key]) { seen[key].count++; return; }
    seen[key] = { kind: kind, class: klass, method: method,
                  args_summary: String(args || '').slice(0, 160), count: 1 };
    send(seen[key]);
}

function hook(className, methodName, kind, summarise) {
    try {
        var cls = Java.use(className);
        if (!cls[methodName]) { return; }
        cls[methodName].overloads.forEach(function (ov) {
            ov.implementation = function () {
                try {
                    report(kind, className, methodName,
                           summarise ? summarise.apply(null, arguments) : '');
                } catch (e) { /* never let instrumentation break the sample */ }
                return ov.apply(this, arguments);
            };
        });
    } catch (e) { /* class absent on this API level or in this app */ }
}

Java.perform(function () {
    // --- SMS: OTP interception and silent sending -------------------------
    hook('android.telephony.SmsManager', 'sendTextMessage', 'sms_sent',
         function (dest, sc, text) { return 'to=' + dest + ' body=' + String(text).slice(0, 40); });
    hook('android.telephony.SmsManager', 'sendMultipartTextMessage', 'sms_sent',
         function (dest) { return 'to=' + dest; });
    hook('android.telephony.SmsMessage', 'createFromPdu', 'sms_intercepted');
    hook('android.content.BroadcastReceiver', 'abortBroadcast', 'sms_intercepted');

    // --- Overlay windows --------------------------------------------------
    hook('android.view.WindowManagerImpl', 'addView', 'overlay',
         function (v, params) { return String(params); });

    // --- Accessibility abuse ---------------------------------------------
    hook('android.accessibilityservice.AccessibilityService',
         'onAccessibilityEvent', 'accessibility');
    hook('android.accessibilityservice.AccessibilityService',
         'dispatchGesture', 'accessibility');

    // --- Code the APK does not contain ------------------------------------
    ['dalvik.system.DexClassLoader', 'dalvik.system.PathClassLoader',
     'dalvik.system.InMemoryDexClassLoader'].forEach(function (loader) {
        try {
            var cls = Java.use(loader);
            cls.$init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        report('code_load', loader, '<init>',
                               arguments.length ? String(arguments[0]) : 'in-memory dex');
                    } catch (e) { }
                    return ov.apply(this, arguments);
                };
            });
        } catch (e) { }
    });

    // --- Network, captured before encryption ------------------------------
    hook('java.net.URL', 'openConnection', 'network',
         function () { return String(this); });
    hook('okhttp3.Request$Builder', 'url', 'network',
         function (u) { return String(u); });
    hook('java.net.Socket', 'connect', 'network',
         function (addr) { return String(addr); });

    // --- Collection and discovery ----------------------------------------
    ['getDeviceId', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number']
        .forEach(function (m) {
            hook('android.telephony.TelephonyManager', m, 'device_id');
        });
    hook('android.content.ContentResolver', 'query', 'content_query',
         function (uri) { return String(uri); });
    hook('android.app.ApplicationPackageManager', 'getInstalledPackages',
         'package_enum');
    hook('java.lang.Runtime', 'exec', 'exec',
         function (cmd) { return String(cmd); });

    // --- Runtime permission prompts ---------------------------------------
    hook('android.app.Activity', 'requestPermissions', 'permission',
         function (perms) { return String(perms); });

    send({ kind: 'ready', class: '', method: '', args_summary: '', count: 1 });
});
