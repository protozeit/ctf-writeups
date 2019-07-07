package org.apache.cordova.whitelist;

import android.content.Context;
import org.apache.cordova.ConfigXmlParser;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.LOG;
import org.apache.cordova.Whitelist;
import org.xmlpull.v1.XmlPullParser;

public class WhitelistPlugin extends CordovaPlugin {
    private static final String LOG_TAG = "WhitelistPlugin";
    /* access modifiers changed from: private */
    public Whitelist allowedIntents;
    /* access modifiers changed from: private */
    public Whitelist allowedNavigations;
    /* access modifiers changed from: private */
    public Whitelist allowedRequests;

    private class CustomConfigXmlParser extends ConfigXmlParser {
        private CustomConfigXmlParser() {
        }

        public void handleStartTag(XmlPullParser xml) {
            boolean external;
            boolean z = true;
            String strNode = xml.getName();
            if (strNode.equals("content")) {
                WhitelistPlugin.this.allowedNavigations.addWhiteListEntry(xml.getAttributeValue(null, "src"), false);
            } else if (strNode.equals("allow-navigation")) {
                String origin = xml.getAttributeValue(null, "href");
                if ("*".equals(origin)) {
                    WhitelistPlugin.this.allowedNavigations.addWhiteListEntry("http://*/*", false);
                    WhitelistPlugin.this.allowedNavigations.addWhiteListEntry("https://*/*", false);
                    WhitelistPlugin.this.allowedNavigations.addWhiteListEntry("data:*", false);
                    return;
                }
                WhitelistPlugin.this.allowedNavigations.addWhiteListEntry(origin, false);
            } else if (strNode.equals("allow-intent")) {
                WhitelistPlugin.this.allowedIntents.addWhiteListEntry(xml.getAttributeValue(null, "href"), false);
            } else if (strNode.equals("access")) {
                String origin2 = xml.getAttributeValue(null, "origin");
                String subdomains = xml.getAttributeValue(null, "subdomains");
                if (xml.getAttributeValue(null, "launch-external") != null) {
                    external = true;
                } else {
                    external = false;
                }
                if (origin2 == null) {
                    return;
                }
                if (external) {
                    LOG.m12w(WhitelistPlugin.LOG_TAG, "Found <access launch-external> within config.xml. Please use <allow-intent> instead.");
                    Whitelist access$200 = WhitelistPlugin.this.allowedIntents;
                    if (subdomains == null || subdomains.compareToIgnoreCase("true") != 0) {
                        z = false;
                    }
                    access$200.addWhiteListEntry(origin2, z);
                } else if ("*".equals(origin2)) {
                    WhitelistPlugin.this.allowedRequests.addWhiteListEntry("http://*/*", false);
                    WhitelistPlugin.this.allowedRequests.addWhiteListEntry("https://*/*", false);
                } else {
                    Whitelist access$300 = WhitelistPlugin.this.allowedRequests;
                    if (subdomains == null || subdomains.compareToIgnoreCase("true") != 0) {
                        z = false;
                    }
                    access$300.addWhiteListEntry(origin2, z);
                }
            }
        }

        public void handleEndTag(XmlPullParser xml) {
        }
    }

    public WhitelistPlugin() {
    }

    public WhitelistPlugin(Context context) {
        this(new Whitelist(), new Whitelist(), null);
        new CustomConfigXmlParser().parse(context);
    }

    public WhitelistPlugin(XmlPullParser xmlParser) {
        this(new Whitelist(), new Whitelist(), null);
        new CustomConfigXmlParser().parse(xmlParser);
    }

    public WhitelistPlugin(Whitelist allowedNavigations2, Whitelist allowedIntents2, Whitelist allowedRequests2) {
        if (allowedRequests2 == null) {
            allowedRequests2 = new Whitelist();
            allowedRequests2.addWhiteListEntry("file:///*", false);
            allowedRequests2.addWhiteListEntry("data:*", false);
        }
        this.allowedNavigations = allowedNavigations2;
        this.allowedIntents = allowedIntents2;
        this.allowedRequests = allowedRequests2;
    }

    public void pluginInitialize() {
        if (this.allowedNavigations == null) {
            this.allowedNavigations = new Whitelist();
            this.allowedIntents = new Whitelist();
            this.allowedRequests = new Whitelist();
            new CustomConfigXmlParser().parse(this.webView.getContext());
        }
    }

    public Boolean shouldAllowNavigation(String url) {
        if (this.allowedNavigations.isUrlWhiteListed(url)) {
            return Boolean.valueOf(true);
        }
        return null;
    }

    public Boolean shouldAllowRequest(String url) {
        if (Boolean.TRUE == shouldAllowNavigation(url)) {
            return Boolean.valueOf(true);
        }
        if (this.allowedRequests.isUrlWhiteListed(url)) {
            return Boolean.valueOf(true);
        }
        return null;
    }

    public Boolean shouldOpenExternalUrl(String url) {
        if (this.allowedIntents.isUrlWhiteListed(url)) {
            return Boolean.valueOf(true);
        }
        return null;
    }

    public Whitelist getAllowedNavigations() {
        return this.allowedNavigations;
    }

    public void setAllowedNavigations(Whitelist allowedNavigations2) {
        this.allowedNavigations = allowedNavigations2;
    }

    public Whitelist getAllowedIntents() {
        return this.allowedIntents;
    }

    public void setAllowedIntents(Whitelist allowedIntents2) {
        this.allowedIntents = allowedIntents2;
    }

    public Whitelist getAllowedRequests() {
        return this.allowedRequests;
    }

    public void setAllowedRequests(Whitelist allowedRequests2) {
        this.allowedRequests = allowedRequests2;
    }
}
