package com.radix.testnet;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * The only thing persisted locally: the node address. The app holds no keys, so
 * there is no key material to protect and no keystore to get wrong.
 */
final class Prefs {

    private static final String FILE = "radix";
    private static final String KEY_NODE = "node_url";
    static final String DEFAULT_NODE = "http://192.168.1.10:8642";

    private Prefs() {
    }

    static String nodeUrl(Context context) {
        return context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
                .getString(KEY_NODE, DEFAULT_NODE);
    }

    static void setNodeUrl(Context context, String url) {
        SharedPreferences.Editor editor = context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit();
        editor.putString(KEY_NODE, url.trim());
        editor.apply();
    }
}
