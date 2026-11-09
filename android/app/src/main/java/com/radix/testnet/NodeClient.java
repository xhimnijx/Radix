package com.radix.testnet;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * The only way this app talks to the world: plain HTTP to a Radix node on the local
 * network. No third-party HTTP library, because the fewer things that can fail to
 * download at build time the better.
 *
 * The timeouts are deliberately long: signing on the Python backend takes one to two
 * minutes, and a wallet that gives up after 30 seconds would report a failure for a
 * transaction that actually succeeded.
 */
final class NodeClient {

    private final String baseUrl;

    NodeClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1)
                : baseUrl;
    }

    String get(String path) throws IOException {
        HttpURLConnection connection = open(path);
        try {
            int code = connection.getResponseCode();
            String body = read(code >= 400 ? connection.getErrorStream() : connection.getInputStream());
            if (code >= 400) {
                throw new IOException("HTTP " + code + ": " + body);
            }
            return body;
        } finally {
            connection.disconnect();
        }
    }

    String postJson(String path, String json) throws IOException {
        HttpURLConnection connection = open(path);
        try {
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            byte[] payload = json.getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(payload.length);
            connection.getOutputStream().write(payload);
            int code = connection.getResponseCode();
            String body = read(code >= 400 ? connection.getErrorStream() : connection.getInputStream());
            if (code >= 400) {
                throw new IOException("HTTP " + code + ": " + body);
            }
            return body;
        } finally {
            connection.disconnect();
        }
    }

    Bitmap getBitmap(String path) throws IOException {
        HttpURLConnection connection = open(path);
        try {
            int code = connection.getResponseCode();
            if (code >= 400) {
                throw new IOException("HTTP " + code);
            }
            InputStream stream = connection.getInputStream();
            Bitmap bitmap = BitmapFactory.decodeStream(stream);
            stream.close();
            if (bitmap == null) {
                throw new IOException("the node did not return an image");
            }
            return bitmap;
        } finally {
            connection.disconnect();
        }
    }

    private HttpURLConnection open(String path) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        connection.setConnectTimeout(8000);
        // Long enough for a real proof on the slow backend.
        connection.setReadTimeout(600000);
        connection.setRequestProperty("Accept", "application/json");
        return connection;
    }

    private static String read(InputStream stream) throws IOException {
        if (stream == null) {
            return "";
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = stream.read(chunk)) != -1) {
            buffer.write(chunk, 0, read);
        }
        stream.close();
        return buffer.toString("UTF-8");
    }
}
