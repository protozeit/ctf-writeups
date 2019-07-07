package org.apache.cordova;

public final class PluginEntry {
    public final boolean onload;
    public final CordovaPlugin plugin;
    public final String pluginClass;
    public final String service;

    public PluginEntry(String service2, CordovaPlugin plugin2) {
        this(service2, plugin2.getClass().getName(), true, plugin2);
    }

    public PluginEntry(String service2, String pluginClass2, boolean onload2) {
        this(service2, pluginClass2, onload2, null);
    }

    private PluginEntry(String service2, String pluginClass2, boolean onload2, CordovaPlugin plugin2) {
        this.service = service2;
        this.pluginClass = pluginClass2;
        this.onload = onload2;
        this.plugin = plugin2;
    }
}
