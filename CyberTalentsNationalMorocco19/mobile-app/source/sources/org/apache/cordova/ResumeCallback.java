package org.apache.cordova;

public class ResumeCallback extends CallbackContext {
    private final String TAG = "CordovaResumeCallback";
    private PluginManager pluginManager;
    private String serviceName;

    public ResumeCallback(String serviceName2, PluginManager pluginManager2) {
        super("resumecallback", null);
        this.serviceName = serviceName2;
        this.pluginManager = pluginManager2;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:?, code lost:
        r4.put("pluginServiceName", r9.serviceName);
        r4.put("pluginStatus", org.apache.cordova.PluginResult.StatusMessages[r10.getStatus()]);
        r2.put("action", "resume");
        r2.put("pendingResult", r4);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x008a, code lost:
        org.apache.cordova.LOG.m3e("CordovaResumeCallback", "Unable to create resume object for Activity Result");
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x002f, code lost:
        r2 = new org.json.JSONObject();
        r4 = new org.json.JSONObject();
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void sendPluginResult(org.apache.cordova.PluginResult r10) {
        /*
            r9 = this;
            monitor-enter(r9)
            boolean r6 = r9.finished     // Catch:{ all -> 0x0086 }
            if (r6 == 0) goto L_0x002b
            java.lang.String r6 = "CordovaResumeCallback"
            java.lang.StringBuilder r7 = new java.lang.StringBuilder     // Catch:{ all -> 0x0086 }
            r7.<init>()     // Catch:{ all -> 0x0086 }
            java.lang.String r8 = r9.serviceName     // Catch:{ all -> 0x0086 }
            java.lang.StringBuilder r7 = r7.append(r8)     // Catch:{ all -> 0x0086 }
            java.lang.String r8 = " attempted to send a second callback to ResumeCallback\nResult was: "
            java.lang.StringBuilder r7 = r7.append(r8)     // Catch:{ all -> 0x0086 }
            java.lang.String r8 = r10.getMessage()     // Catch:{ all -> 0x0086 }
            java.lang.StringBuilder r7 = r7.append(r8)     // Catch:{ all -> 0x0086 }
            java.lang.String r7 = r7.toString()     // Catch:{ all -> 0x0086 }
            org.apache.cordova.LOG.m12w(r6, r7)     // Catch:{ all -> 0x0086 }
            monitor-exit(r9)     // Catch:{ all -> 0x0086 }
        L_0x002a:
            return
        L_0x002b:
            r6 = 1
            r9.finished = r6     // Catch:{ all -> 0x0086 }
            monitor-exit(r9)     // Catch:{ all -> 0x0086 }
            org.json.JSONObject r2 = new org.json.JSONObject
            r2.<init>()
            org.json.JSONObject r4 = new org.json.JSONObject
            r4.<init>()
            java.lang.String r6 = "pluginServiceName"
            java.lang.String r7 = r9.serviceName     // Catch:{ JSONException -> 0x0089 }
            r4.put(r6, r7)     // Catch:{ JSONException -> 0x0089 }
            java.lang.String r6 = "pluginStatus"
            java.lang.String[] r7 = org.apache.cordova.PluginResult.StatusMessages     // Catch:{ JSONException -> 0x0089 }
            int r8 = r10.getStatus()     // Catch:{ JSONException -> 0x0089 }
            r7 = r7[r8]     // Catch:{ JSONException -> 0x0089 }
            r4.put(r6, r7)     // Catch:{ JSONException -> 0x0089 }
            java.lang.String r6 = "action"
            java.lang.String r7 = "resume"
            r2.put(r6, r7)     // Catch:{ JSONException -> 0x0089 }
            java.lang.String r6 = "pendingResult"
            r2.put(r6, r4)     // Catch:{ JSONException -> 0x0089 }
        L_0x005e:
            org.apache.cordova.PluginResult r3 = new org.apache.cordova.PluginResult
            org.apache.cordova.PluginResult$Status r6 = org.apache.cordova.PluginResult.Status.OK
            r3.<init>(r6, r2)
            java.util.ArrayList r5 = new java.util.ArrayList
            r5.<init>()
            r5.add(r3)
            r5.add(r10)
            org.apache.cordova.PluginManager r6 = r9.pluginManager
            java.lang.String r7 = "CoreAndroid"
            org.apache.cordova.CordovaPlugin r0 = r6.getPlugin(r7)
            org.apache.cordova.CoreAndroid r0 = (org.apache.cordova.CoreAndroid) r0
            org.apache.cordova.PluginResult r6 = new org.apache.cordova.PluginResult
            org.apache.cordova.PluginResult$Status r7 = org.apache.cordova.PluginResult.Status.OK
            r6.<init>(r7, r5)
            r0.sendResumeEvent(r6)
            goto L_0x002a
        L_0x0086:
            r6 = move-exception
            monitor-exit(r9)     // Catch:{ all -> 0x0086 }
            throw r6
        L_0x0089:
            r1 = move-exception
            java.lang.String r6 = "CordovaResumeCallback"
            java.lang.String r7 = "Unable to create resume object for Activity Result"
            org.apache.cordova.LOG.m3e(r6, r7)
            goto L_0x005e
        */
        throw new UnsupportedOperationException("Method not decompiled: org.apache.cordova.ResumeCallback.sendPluginResult(org.apache.cordova.PluginResult):void");
    }
}
