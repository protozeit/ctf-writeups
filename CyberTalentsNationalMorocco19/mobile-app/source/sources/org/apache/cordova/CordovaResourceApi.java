package org.apache.cordova;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.content.res.AssetManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Looper;
import android.util.Base64;
import android.webkit.MimeTypeMap;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.channels.FileChannel;
import java.util.Locale;

public class CordovaResourceApi {
    private static final String[] LOCAL_FILE_PROJECTION = {"_data"};
    private static final String LOG_TAG = "CordovaResourceApi";
    public static final String PLUGIN_URI_SCHEME = "cdvplugin";
    public static final int URI_TYPE_ASSET = 1;
    public static final int URI_TYPE_CONTENT = 2;
    public static final int URI_TYPE_DATA = 4;
    public static final int URI_TYPE_FILE = 0;
    public static final int URI_TYPE_HTTP = 5;
    public static final int URI_TYPE_HTTPS = 6;
    public static final int URI_TYPE_PLUGIN = 7;
    public static final int URI_TYPE_RESOURCE = 3;
    public static final int URI_TYPE_UNKNOWN = -1;
    public static Thread jsThread;
    private final AssetManager assetManager;
    private final ContentResolver contentResolver;
    private final PluginManager pluginManager;
    private boolean threadCheckingEnabled = true;

    public static final class OpenForReadResult {
        public final AssetFileDescriptor assetFd;
        public final InputStream inputStream;
        public final long length;
        public final String mimeType;
        public final Uri uri;

        public OpenForReadResult(Uri uri2, InputStream inputStream2, String mimeType2, long length2, AssetFileDescriptor assetFd2) {
            this.uri = uri2;
            this.inputStream = inputStream2;
            this.mimeType = mimeType2;
            this.length = length2;
            this.assetFd = assetFd2;
        }
    }

    public CordovaResourceApi(Context context, PluginManager pluginManager2) {
        this.contentResolver = context.getContentResolver();
        this.assetManager = context.getAssets();
        this.pluginManager = pluginManager2;
    }

    public void setThreadCheckingEnabled(boolean value) {
        this.threadCheckingEnabled = value;
    }

    public boolean isThreadCheckingEnabled() {
        return this.threadCheckingEnabled;
    }

    public static int getUriType(Uri uri) {
        assertNonRelative(uri);
        String scheme = uri.getScheme();
        if ("content".equalsIgnoreCase(scheme)) {
            return 2;
        }
        if ("android.resource".equalsIgnoreCase(scheme)) {
            return 3;
        }
        if ("file".equalsIgnoreCase(scheme)) {
            if (uri.getPath().startsWith("/android_asset/")) {
                return 1;
            }
            return 0;
        } else if ("data".equalsIgnoreCase(scheme)) {
            return 4;
        } else {
            if ("http".equalsIgnoreCase(scheme)) {
                return 5;
            }
            if ("https".equalsIgnoreCase(scheme)) {
                return 6;
            }
            if (PLUGIN_URI_SCHEME.equalsIgnoreCase(scheme)) {
                return 7;
            }
            return -1;
        }
    }

    public Uri remapUri(Uri uri) {
        assertNonRelative(uri);
        Uri pluginUri = this.pluginManager.remapUri(uri);
        return pluginUri != null ? pluginUri : uri;
    }

    public String remapPath(String path) {
        return remapUri(Uri.fromFile(new File(path))).getPath();
    }

    public File mapUriToFile(Uri uri) {
        assertBackgroundThread();
        switch (getUriType(uri)) {
            case URI_TYPE_FILE /*0*/:
                return new File(uri.getPath());
            case 2:
                Cursor cursor = this.contentResolver.query(uri, LOCAL_FILE_PROJECTION, null, null, null);
                if (cursor == null) {
                    return null;
                }
                try {
                    int columnIndex = cursor.getColumnIndex(LOCAL_FILE_PROJECTION[0]);
                    if (columnIndex != -1 && cursor.getCount() > 0) {
                        cursor.moveToFirst();
                        String realPath = cursor.getString(columnIndex);
                        if (realPath != null) {
                            return new File(realPath);
                        }
                    }
                    cursor.close();
                    return null;
                } finally {
                    cursor.close();
                }
            default:
                return null;
        }
    }

    public String getMimeType(Uri uri) {
        switch (getUriType(uri)) {
            case URI_TYPE_FILE /*0*/:
            case 1:
                return getMimeTypeFromPath(uri.getPath());
            case 2:
            case 3:
                return this.contentResolver.getType(uri);
            case 4:
                return getDataUriMimeType(uri);
            case 5:
            case 6:
                try {
                    HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString()).openConnection();
                    conn.setDoInput(false);
                    conn.setRequestMethod("HEAD");
                    String mimeType = conn.getHeaderField("Content-Type");
                    if (mimeType != null) {
                        return mimeType.split(";")[0];
                    }
                    return mimeType;
                } catch (IOException e) {
                    break;
                }
        }
        return null;
    }

    private String getMimeTypeFromPath(String path) {
        String extension = path;
        int lastDot = extension.lastIndexOf(46);
        if (lastDot != -1) {
            extension = extension.substring(lastDot + 1);
        }
        String extension2 = extension.toLowerCase(Locale.getDefault());
        if (extension2.equals("3ga")) {
            return "audio/3gpp";
        }
        if (extension2.equals("js")) {
            return "text/javascript";
        }
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension2);
    }

    public OpenForReadResult openForRead(Uri uri) throws IOException {
        return openForRead(uri, false);
    }

    public OpenForReadResult openForRead(Uri uri, boolean skipThreadCheck) throws IOException {
        InputStream inputStream;
        long length;
        if (!skipThreadCheck) {
            assertBackgroundThread();
        }
        switch (getUriType(uri)) {
            case URI_TYPE_FILE /*0*/:
                FileInputStream inputStream2 = new FileInputStream(uri.getPath());
                return new OpenForReadResult(uri, inputStream2, getMimeTypeFromPath(uri.getPath()), inputStream2.getChannel().size(), null);
            case 1:
                String assetPath = uri.getPath().substring(15);
                AssetFileDescriptor assetFd = null;
                try {
                    assetFd = this.assetManager.openFd(assetPath);
                    inputStream = assetFd.createInputStream();
                    length = assetFd.getLength();
                } catch (FileNotFoundException e) {
                    inputStream = this.assetManager.open(assetPath);
                    length = (long) inputStream.available();
                }
                return new OpenForReadResult(uri, inputStream, getMimeTypeFromPath(assetPath), length, assetFd);
            case 2:
            case 3:
                String mimeType = this.contentResolver.getType(uri);
                AssetFileDescriptor assetFd2 = this.contentResolver.openAssetFileDescriptor(uri, "r");
                return new OpenForReadResult(uri, assetFd2.createInputStream(), mimeType, assetFd2.getLength(), assetFd2);
            case 4:
                OpenForReadResult ret = readDataUri(uri);
                if (ret != null) {
                    return ret;
                }
                break;
            case 5:
            case 6:
                HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString()).openConnection();
                conn.setDoInput(true);
                String mimeType2 = conn.getHeaderField("Content-Type");
                if (mimeType2 != null) {
                    mimeType2 = mimeType2.split(";")[0];
                }
                int length2 = conn.getContentLength();
                return new OpenForReadResult(uri, conn.getInputStream(), mimeType2, (long) length2, null);
            case 7:
                CordovaPlugin plugin = this.pluginManager.getPlugin(uri.getHost());
                if (plugin != null) {
                    return plugin.handleOpenForRead(uri);
                }
                throw new FileNotFoundException("Invalid plugin ID in URI: " + uri);
        }
        throw new FileNotFoundException("URI not supported by CordovaResourceApi: " + uri);
    }

    public OutputStream openOutputStream(Uri uri) throws IOException {
        return openOutputStream(uri, false);
    }

    public OutputStream openOutputStream(Uri uri, boolean append) throws IOException {
        assertBackgroundThread();
        switch (getUriType(uri)) {
            case URI_TYPE_FILE /*0*/:
                File localFile = new File(uri.getPath());
                File parent = localFile.getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                return new FileOutputStream(localFile, append);
            case 2:
            case 3:
                return this.contentResolver.openAssetFileDescriptor(uri, append ? "wa" : "w").createOutputStream();
            default:
                throw new FileNotFoundException("URI not supported by CordovaResourceApi: " + uri);
        }
    }

    public HttpURLConnection createHttpConnection(Uri uri) throws IOException {
        assertBackgroundThread();
        return (HttpURLConnection) new URL(uri.toString()).openConnection();
    }

    public void copyResource(OpenForReadResult input, OutputStream outputStream) throws IOException {
        assertBackgroundThread();
        try {
            InputStream inputStream = input.inputStream;
            if (!(inputStream instanceof FileInputStream) || !(outputStream instanceof FileOutputStream)) {
                byte[] buffer = new byte[8192];
                while (true) {
                    int bytesRead = inputStream.read(buffer, 0, 8192);
                    if (bytesRead <= 0) {
                        break;
                    }
                    outputStream.write(buffer, 0, bytesRead);
                }
            } else {
                FileChannel inChannel = ((FileInputStream) input.inputStream).getChannel();
                FileChannel outChannel = ((FileOutputStream) outputStream).getChannel();
                long offset = 0;
                long length = input.length;
                if (input.assetFd != null) {
                    offset = input.assetFd.getStartOffset();
                }
                inChannel.position(offset);
                outChannel.transferFrom(inChannel, 0, length);
            }
        } finally {
            input.inputStream.close();
            if (outputStream != null) {
                outputStream.close();
            }
        }
    }

    public void copyResource(Uri sourceUri, OutputStream outputStream) throws IOException {
        copyResource(openForRead(sourceUri), outputStream);
    }

    public void copyResource(Uri sourceUri, Uri dstUri) throws IOException {
        copyResource(openForRead(sourceUri), openOutputStream(dstUri));
    }

    private void assertBackgroundThread() {
        if (this.threadCheckingEnabled) {
            Thread curThread = Thread.currentThread();
            if (curThread == Looper.getMainLooper().getThread()) {
                throw new IllegalStateException("Do not perform IO operations on the UI thread. Use CordovaInterface.getThreadPool() instead.");
            } else if (curThread == jsThread) {
                throw new IllegalStateException("Tried to perform an IO operation on the WebCore thread. Use CordovaInterface.getThreadPool() instead.");
            }
        }
    }

    private String getDataUriMimeType(Uri uri) {
        String uriAsString = uri.getSchemeSpecificPart();
        int commaPos = uriAsString.indexOf(44);
        if (commaPos == -1) {
            return null;
        }
        String[] mimeParts = uriAsString.substring(0, commaPos).split(";");
        if (mimeParts.length > 0) {
            return mimeParts[0];
        }
        return null;
    }

    private OpenForReadResult readDataUri(Uri uri) {
        byte[] data;
        String uriAsString = uri.getSchemeSpecificPart();
        int commaPos = uriAsString.indexOf(44);
        if (commaPos == -1) {
            return null;
        }
        String[] mimeParts = uriAsString.substring(0, commaPos).split(";");
        String contentType = null;
        boolean base64 = false;
        if (mimeParts.length > 0) {
            contentType = mimeParts[0];
        }
        for (int i = 1; i < mimeParts.length; i++) {
            if ("base64".equalsIgnoreCase(mimeParts[i])) {
                base64 = true;
            }
        }
        String dataPartAsString = uriAsString.substring(commaPos + 1);
        if (base64) {
            data = Base64.decode(dataPartAsString, 0);
        } else {
            try {
                data = dataPartAsString.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                data = dataPartAsString.getBytes();
            }
        }
        return new OpenForReadResult(uri, new ByteArrayInputStream(data), contentType, (long) data.length, null);
    }

    private static void assertNonRelative(Uri uri) {
        if (!uri.isAbsolute()) {
            throw new IllegalArgumentException("Relative URIs are not supported.");
        }
    }
}
