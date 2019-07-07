package org.apache.cordova;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import org.apache.cordova.PluginResult.Status;

public class NativeToJsMessageQueue {
    static final boolean DISABLE_EXEC_CHAINING = false;
    private static final boolean FORCE_ENCODE_USING_EVAL = false;
    private static final String LOG_TAG = "JsMessageQueue";
    private static int MAX_PAYLOAD_SIZE = 524288000;
    private BridgeMode activeBridgeMode;
    private ArrayList<BridgeMode> bridgeModes = new ArrayList<>();
    private boolean paused;
    private final LinkedList<JsMessage> queue = new LinkedList<>();

    public static abstract class BridgeMode {
        public abstract void onNativeToJsMessageAvailable(NativeToJsMessageQueue nativeToJsMessageQueue);

        public void notifyOfFlush(NativeToJsMessageQueue queue, boolean fromOnlineEvent) {
        }

        public void reset() {
        }
    }

    public static class EvalBridgeMode extends BridgeMode {
        private final CordovaInterface cordova;
        /* access modifiers changed from: private */
        public final CordovaWebViewEngine engine;

        public EvalBridgeMode(CordovaWebViewEngine engine2, CordovaInterface cordova2) {
            this.engine = engine2;
            this.cordova = cordova2;
        }

        public void onNativeToJsMessageAvailable(final NativeToJsMessageQueue queue) {
            this.cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    String js = queue.popAndEncodeAsJs();
                    if (js != null) {
                        EvalBridgeMode.this.engine.evaluateJavascript(js, null);
                    }
                }
            });
        }
    }

    private static class JsMessage {
        final String jsPayloadOrCallbackId;
        final PluginResult pluginResult;

        JsMessage(String js) {
            if (js == null) {
                throw new NullPointerException();
            }
            this.jsPayloadOrCallbackId = js;
            this.pluginResult = null;
        }

        JsMessage(PluginResult pluginResult2, String callbackId) {
            if (callbackId == null || pluginResult2 == null) {
                throw new NullPointerException();
            }
            this.jsPayloadOrCallbackId = callbackId;
            this.pluginResult = pluginResult2;
        }

        static int calculateEncodedLengthHelper(PluginResult pluginResult2) {
            switch (pluginResult2.getMessageType()) {
                case 1:
                    return pluginResult2.getStrMessage().length() + 1;
                case 3:
                    return pluginResult2.getMessage().length() + 1;
                case 4:
                case 5:
                    return 1;
                case 6:
                    return pluginResult2.getMessage().length() + 1;
                case 7:
                    return pluginResult2.getMessage().length() + 1;
                case PluginResult.MESSAGE_TYPE_MULTIPART /*8*/:
                    int ret = 1;
                    for (int i = 0; i < pluginResult2.getMultipartMessagesSize(); i++) {
                        int length = calculateEncodedLengthHelper(pluginResult2.getMultipartMessage(i));
                        ret += String.valueOf(length).length() + 1 + length;
                    }
                    return ret;
                default:
                    return pluginResult2.getMessage().length();
            }
        }

        /* access modifiers changed from: 0000 */
        public int calculateEncodedLength() {
            if (this.pluginResult == null) {
                return this.jsPayloadOrCallbackId.length() + 1;
            }
            return calculateEncodedLengthHelper(this.pluginResult) + String.valueOf(this.pluginResult.getStatus()).length() + 2 + 1 + this.jsPayloadOrCallbackId.length() + 1;
        }

        static void encodeAsMessageHelper(StringBuilder sb, PluginResult pluginResult2) {
            switch (pluginResult2.getMessageType()) {
                case 1:
                    sb.append('s');
                    sb.append(pluginResult2.getStrMessage());
                    return;
                case 3:
                    sb.append('n').append(pluginResult2.getMessage());
                    return;
                case 4:
                    sb.append(pluginResult2.getMessage().charAt(0));
                    return;
                case 5:
                    sb.append('N');
                    return;
                case 6:
                    sb.append('A');
                    sb.append(pluginResult2.getMessage());
                    return;
                case 7:
                    sb.append('S');
                    sb.append(pluginResult2.getMessage());
                    return;
                case PluginResult.MESSAGE_TYPE_MULTIPART /*8*/:
                    sb.append('M');
                    for (int i = 0; i < pluginResult2.getMultipartMessagesSize(); i++) {
                        PluginResult multipartMessage = pluginResult2.getMultipartMessage(i);
                        sb.append(String.valueOf(calculateEncodedLengthHelper(multipartMessage)));
                        sb.append(' ');
                        encodeAsMessageHelper(sb, multipartMessage);
                    }
                    return;
                default:
                    sb.append(pluginResult2.getMessage());
                    return;
            }
        }

        /* access modifiers changed from: 0000 */
        public void encodeAsMessage(StringBuilder sb) {
            boolean noResult;
            boolean resultOk;
            if (this.pluginResult == null) {
                sb.append('J').append(this.jsPayloadOrCallbackId);
                return;
            }
            int status = this.pluginResult.getStatus();
            if (status == Status.NO_RESULT.ordinal()) {
                noResult = true;
            } else {
                noResult = false;
            }
            if (status == Status.OK.ordinal()) {
                resultOk = true;
            } else {
                resultOk = false;
            }
            sb.append((noResult || resultOk) ? 'S' : 'F').append(this.pluginResult.getKeepCallback() ? '1' : '0').append(status).append(' ').append(this.jsPayloadOrCallbackId).append(' ');
            encodeAsMessageHelper(sb, this.pluginResult);
        }

        /* access modifiers changed from: 0000 */
        public void buildJsMessage(StringBuilder sb) {
            switch (this.pluginResult.getMessageType()) {
                case 5:
                    sb.append("null");
                    return;
                case 6:
                    sb.append("cordova.require('cordova/base64').toArrayBuffer('").append(this.pluginResult.getMessage()).append("')");
                    return;
                case 7:
                    sb.append("atob('").append(this.pluginResult.getMessage()).append("')");
                    return;
                case PluginResult.MESSAGE_TYPE_MULTIPART /*8*/:
                    int size = this.pluginResult.getMultipartMessagesSize();
                    for (int i = 0; i < size; i++) {
                        new JsMessage(this.pluginResult.getMultipartMessage(i), this.jsPayloadOrCallbackId).buildJsMessage(sb);
                        if (i < size - 1) {
                            sb.append(",");
                        }
                    }
                    return;
                default:
                    sb.append(this.pluginResult.getMessage());
                    return;
            }
        }

        /* access modifiers changed from: 0000 */
        public void encodeAsJsMessage(StringBuilder sb) {
            if (this.pluginResult == null) {
                sb.append(this.jsPayloadOrCallbackId);
                return;
            }
            int status = this.pluginResult.getStatus();
            sb.append("cordova.callbackFromNative('").append(this.jsPayloadOrCallbackId).append("',").append(status == Status.OK.ordinal() || status == Status.NO_RESULT.ordinal()).append(",").append(status).append(",[");
            buildJsMessage(sb);
            sb.append("],").append(this.pluginResult.getKeepCallback()).append(");");
        }
    }

    public static class LoadUrlBridgeMode extends BridgeMode {
        private final CordovaInterface cordova;
        /* access modifiers changed from: private */
        public final CordovaWebViewEngine engine;

        public LoadUrlBridgeMode(CordovaWebViewEngine engine2, CordovaInterface cordova2) {
            this.engine = engine2;
            this.cordova = cordova2;
        }

        public void onNativeToJsMessageAvailable(final NativeToJsMessageQueue queue) {
            this.cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    String js = queue.popAndEncodeAsJs();
                    if (js != null) {
                        LoadUrlBridgeMode.this.engine.loadUrl("javascript:" + js, false);
                    }
                }
            });
        }
    }

    public static class NoOpBridgeMode extends BridgeMode {
        public void onNativeToJsMessageAvailable(NativeToJsMessageQueue queue) {
        }
    }

    public static class OnlineEventsBridgeMode extends BridgeMode {
        /* access modifiers changed from: private */
        public final OnlineEventsBridgeModeDelegate delegate;
        /* access modifiers changed from: private */
        public boolean ignoreNextFlush;
        /* access modifiers changed from: private */
        public boolean online;

        public interface OnlineEventsBridgeModeDelegate {
            void runOnUiThread(Runnable runnable);

            void setNetworkAvailable(boolean z);
        }

        public OnlineEventsBridgeMode(OnlineEventsBridgeModeDelegate delegate2) {
            this.delegate = delegate2;
        }

        public void reset() {
            this.delegate.runOnUiThread(new Runnable() {
                public void run() {
                    OnlineEventsBridgeMode.this.online = false;
                    OnlineEventsBridgeMode.this.ignoreNextFlush = true;
                    OnlineEventsBridgeMode.this.delegate.setNetworkAvailable(true);
                }
            });
        }

        public void onNativeToJsMessageAvailable(final NativeToJsMessageQueue queue) {
            this.delegate.runOnUiThread(new Runnable() {
                public void run() {
                    if (!queue.isEmpty()) {
                        OnlineEventsBridgeMode.this.ignoreNextFlush = false;
                        OnlineEventsBridgeMode.this.delegate.setNetworkAvailable(OnlineEventsBridgeMode.this.online);
                    }
                }
            });
        }

        public void notifyOfFlush(NativeToJsMessageQueue queue, boolean fromOnlineEvent) {
            if (fromOnlineEvent && !this.ignoreNextFlush) {
                this.online = !this.online;
            }
        }
    }

    public void addBridgeMode(BridgeMode bridgeMode) {
        this.bridgeModes.add(bridgeMode);
    }

    public boolean isBridgeEnabled() {
        return this.activeBridgeMode != null;
    }

    public boolean isEmpty() {
        return this.queue.isEmpty();
    }

    public void setBridgeMode(int value) {
        if (value < -1 || value >= this.bridgeModes.size()) {
            LOG.m0d(LOG_TAG, "Invalid NativeToJsBridgeMode: " + value);
            return;
        }
        BridgeMode newMode = value < 0 ? null : (BridgeMode) this.bridgeModes.get(value);
        if (newMode != this.activeBridgeMode) {
            LOG.m0d(LOG_TAG, "Set native->JS mode to " + (newMode == null ? "null" : newMode.getClass().getSimpleName()));
            synchronized (this) {
                this.activeBridgeMode = newMode;
                if (newMode != null) {
                    newMode.reset();
                    if (!this.paused && !this.queue.isEmpty()) {
                        newMode.onNativeToJsMessageAvailable(this);
                    }
                }
            }
        }
    }

    public void reset() {
        synchronized (this) {
            this.queue.clear();
            setBridgeMode(-1);
        }
    }

    private int calculatePackedMessageLength(JsMessage message) {
        int messageLen = message.calculateEncodedLength();
        return String.valueOf(messageLen).length() + messageLen + 1;
    }

    private void packMessage(JsMessage message, StringBuilder sb) {
        sb.append(message.calculateEncodedLength()).append(' ');
        message.encodeAsMessage(sb);
    }

    public String popAndEncode(boolean fromOnlineEvent) {
        String str = null;
        synchronized (this) {
            if (this.activeBridgeMode != null) {
                this.activeBridgeMode.notifyOfFlush(this, fromOnlineEvent);
                if (!this.queue.isEmpty()) {
                    int totalPayloadLen = 0;
                    int numMessagesToSend = 0;
                    Iterator it = this.queue.iterator();
                    while (it.hasNext()) {
                        int messageSize = calculatePackedMessageLength((JsMessage) it.next());
                        if (numMessagesToSend > 0 && totalPayloadLen + messageSize > MAX_PAYLOAD_SIZE && MAX_PAYLOAD_SIZE > 0) {
                            break;
                        }
                        totalPayloadLen += messageSize;
                        numMessagesToSend++;
                    }
                    StringBuilder sb = new StringBuilder(totalPayloadLen);
                    for (int i = 0; i < numMessagesToSend; i++) {
                        packMessage((JsMessage) this.queue.removeFirst(), sb);
                    }
                    if (!this.queue.isEmpty()) {
                        sb.append('*');
                    }
                    str = sb.toString();
                }
            }
        }
        return str;
    }

    public String popAndEncodeAsJs() {
        boolean willSendAllMessages;
        String sb;
        synchronized (this) {
            if (this.queue.size() == 0) {
                sb = null;
            } else {
                int totalPayloadLen = 0;
                int numMessagesToSend = 0;
                Iterator it = this.queue.iterator();
                while (it.hasNext()) {
                    int messageSize = ((JsMessage) it.next()).calculateEncodedLength() + 50;
                    if (numMessagesToSend > 0 && totalPayloadLen + messageSize > MAX_PAYLOAD_SIZE && MAX_PAYLOAD_SIZE > 0) {
                        break;
                    }
                    totalPayloadLen += messageSize;
                    numMessagesToSend++;
                }
                if (numMessagesToSend == this.queue.size()) {
                    willSendAllMessages = true;
                } else {
                    willSendAllMessages = false;
                }
                StringBuilder sb2 = new StringBuilder((willSendAllMessages ? 0 : 100) + totalPayloadLen);
                for (int i = 0; i < numMessagesToSend; i++) {
                    JsMessage message = (JsMessage) this.queue.removeFirst();
                    if (!willSendAllMessages || i + 1 != numMessagesToSend) {
                        sb2.append("try{");
                        message.encodeAsJsMessage(sb2);
                        sb2.append("}finally{");
                    } else {
                        message.encodeAsJsMessage(sb2);
                    }
                }
                if (!willSendAllMessages) {
                    sb2.append("window.setTimeout(function(){cordova.require('cordova/plugin/android/polling').pollOnce();},0);");
                }
                for (int i2 = willSendAllMessages ? 1 : 0; i2 < numMessagesToSend; i2++) {
                    sb2.append('}');
                }
                sb = sb2.toString();
            }
        }
        return sb;
    }

    public void addJavaScript(String statement) {
        enqueueMessage(new JsMessage(statement));
    }

    public void addPluginResult(PluginResult result, String callbackId) {
        if (callbackId == null) {
            LOG.m4e(LOG_TAG, "Got plugin result with no callbackId", new Throwable());
            return;
        }
        boolean noResult = result.getStatus() == Status.NO_RESULT.ordinal();
        boolean keepCallback = result.getKeepCallback();
        if (!noResult || !keepCallback) {
            enqueueMessage(new JsMessage(result, callbackId));
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:15:?, code lost:
        return;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private void enqueueMessage(org.apache.cordova.NativeToJsMessageQueue.JsMessage r3) {
        /*
            r2 = this;
            monitor-enter(r2)
            org.apache.cordova.NativeToJsMessageQueue$BridgeMode r0 = r2.activeBridgeMode     // Catch:{ all -> 0x0020 }
            if (r0 != 0) goto L_0x0010
            java.lang.String r0 = "JsMessageQueue"
            java.lang.String r1 = "Dropping Native->JS message due to disabled bridge"
            org.apache.cordova.LOG.m0d(r0, r1)     // Catch:{ all -> 0x0020 }
            monitor-exit(r2)     // Catch:{ all -> 0x0020 }
        L_0x000f:
            return
        L_0x0010:
            java.util.LinkedList<org.apache.cordova.NativeToJsMessageQueue$JsMessage> r0 = r2.queue     // Catch:{ all -> 0x0020 }
            r0.add(r3)     // Catch:{ all -> 0x0020 }
            boolean r0 = r2.paused     // Catch:{ all -> 0x0020 }
            if (r0 != 0) goto L_0x001e
            org.apache.cordova.NativeToJsMessageQueue$BridgeMode r0 = r2.activeBridgeMode     // Catch:{ all -> 0x0020 }
            r0.onNativeToJsMessageAvailable(r2)     // Catch:{ all -> 0x0020 }
        L_0x001e:
            monitor-exit(r2)     // Catch:{ all -> 0x0020 }
            goto L_0x000f
        L_0x0020:
            r0 = move-exception
            monitor-exit(r2)     // Catch:{ all -> 0x0020 }
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.apache.cordova.NativeToJsMessageQueue.enqueueMessage(org.apache.cordova.NativeToJsMessageQueue$JsMessage):void");
    }

    public void setPaused(boolean value) {
        if (this.paused && value) {
            LOG.m4e(LOG_TAG, "nested call to setPaused detected.", new Throwable());
        }
        this.paused = value;
        if (!value) {
            synchronized (this) {
                if (!this.queue.isEmpty() && this.activeBridgeMode != null) {
                    this.activeBridgeMode.onNativeToJsMessageAvailable(this);
                }
            }
        }
    }
}
