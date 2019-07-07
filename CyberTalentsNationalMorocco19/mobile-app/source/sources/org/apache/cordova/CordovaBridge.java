package org.apache.cordova;

import android.annotation.SuppressLint;
import java.security.SecureRandom;
import org.json.JSONArray;
import org.json.JSONException;

public class CordovaBridge {
    private static final String LOG_TAG = "CordovaBridge";
    private volatile int expectedBridgeSecret = -1;
    private NativeToJsMessageQueue jsMessageQueue;
    private PluginManager pluginManager;

    public CordovaBridge(PluginManager pluginManager2, NativeToJsMessageQueue jsMessageQueue2) {
        this.pluginManager = pluginManager2;
        this.jsMessageQueue = jsMessageQueue2;
    }

    public String jsExec(int bridgeSecret, String service, String action, String callbackId, String arguments) throws JSONException, IllegalAccessException {
        if (!verifySecret("exec()", bridgeSecret)) {
            return null;
        }
        if (arguments == null) {
            return "@Null arguments.";
        }
        this.jsMessageQueue.setPaused(true);
        try {
            CordovaResourceApi.jsThread = Thread.currentThread();
            this.pluginManager.exec(service, action, callbackId, arguments);
            return this.jsMessageQueue.popAndEncode(false);
        } catch (Throwable e) {
            e.printStackTrace();
            return "";
        } finally {
            this.jsMessageQueue.setPaused(false);
        }
    }

    public void jsSetNativeToJsBridgeMode(int bridgeSecret, int value) throws IllegalAccessException {
        if (verifySecret("setNativeToJsBridgeMode()", bridgeSecret)) {
            this.jsMessageQueue.setBridgeMode(value);
        }
    }

    public String jsRetrieveJsMessages(int bridgeSecret, boolean fromOnlineEvent) throws IllegalAccessException {
        if (!verifySecret("retrieveJsMessages()", bridgeSecret)) {
            return null;
        }
        return this.jsMessageQueue.popAndEncode(fromOnlineEvent);
    }

    private boolean verifySecret(String action, int bridgeSecret) throws IllegalAccessException {
        if (!this.jsMessageQueue.isBridgeEnabled()) {
            if (bridgeSecret == -1) {
                LOG.m0d(LOG_TAG, action + " call made before bridge was enabled.");
            } else {
                LOG.m0d(LOG_TAG, "Ignoring " + action + " from previous page load.");
            }
            return false;
        } else if (this.expectedBridgeSecret >= 0 && bridgeSecret == this.expectedBridgeSecret) {
            return true;
        } else {
            LOG.m3e(LOG_TAG, "Bridge access attempt with wrong secret token, possibly from malicious code. Disabling exec() bridge!");
            clearBridgeSecret();
            throw new IllegalAccessException();
        }
    }

    /* access modifiers changed from: 0000 */
    public void clearBridgeSecret() {
        this.expectedBridgeSecret = -1;
    }

    public boolean isSecretEstablished() {
        return this.expectedBridgeSecret != -1;
    }

    /* access modifiers changed from: 0000 */
    @SuppressLint({"TrulyRandom"})
    public int generateBridgeSecret() {
        this.expectedBridgeSecret = new SecureRandom().nextInt(Integer.MAX_VALUE);
        return this.expectedBridgeSecret;
    }

    public void reset() {
        this.jsMessageQueue.reset();
        clearBridgeSecret();
    }

    public String promptOnJsPrompt(String origin, String message, String defaultValue) {
        if (defaultValue != null && defaultValue.length() > 3 && defaultValue.startsWith("gap:")) {
            try {
                JSONArray array = new JSONArray(defaultValue.substring(4));
                String r = jsExec(array.getInt(0), array.getString(1), array.getString(2), array.getString(3), message);
                return r == null ? "" : r;
            } catch (JSONException e) {
                e.printStackTrace();
                return "";
            } catch (IllegalAccessException e2) {
                e2.printStackTrace();
                return "";
            }
        } else if (defaultValue != null && defaultValue.startsWith("gap_bridge_mode:")) {
            try {
                jsSetNativeToJsBridgeMode(Integer.parseInt(defaultValue.substring(16)), Integer.parseInt(message));
            } catch (NumberFormatException e3) {
                e3.printStackTrace();
            } catch (IllegalAccessException e4) {
                e4.printStackTrace();
            }
            return "";
        } else if (defaultValue != null && defaultValue.startsWith("gap_poll:")) {
            try {
                String r2 = jsRetrieveJsMessages(Integer.parseInt(defaultValue.substring(9)), "1".equals(message));
                if (r2 == null) {
                    return "";
                }
                return r2;
            } catch (IllegalAccessException e5) {
                e5.printStackTrace();
                return "";
            }
        } else if (defaultValue == null || !defaultValue.startsWith("gap_init:")) {
            return null;
        } else {
            if (this.pluginManager.shouldAllowBridgeAccess(origin)) {
                this.jsMessageQueue.setBridgeMode(Integer.parseInt(defaultValue.substring(9)));
                return "" + generateBridgeSecret();
            }
            LOG.m3e(LOG_TAG, "gap_init called from restricted origin: " + origin);
            return "";
        }
    }
}
