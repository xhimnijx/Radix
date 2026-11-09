package com.radix.testnet;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * One screen, three dialogs. No AndroidX, no third-party UI library: the whole app
 * is the Android framework plus org.json, which keeps the build to a single
 * dependency (the Android Gradle Plugin) and the APK small.
 *
 * <p>The app is a client. It holds no keys and performs no proving: every spend is
 * signed by the node it is pointed at. That is a deliberate, documented limitation
 * of this build, not an accident.
 */
public final class MainActivity extends Activity {

    private final ExecutorService io = Executors.newSingleThreadExecutor();

    private NodeClient client;
    private TextView nodeText;
    private TextView statusText;
    private TextView balanceText;
    private LinearLayout accountsBox;

    private JSONObject status;
    private List<Account> accounts = new ArrayList<>();

    private static final class Account {
        String name;
        String address;
        String shortAddress;
        long balance;
        int notes;
        boolean spent;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        nodeText = findViewById(R.id.nodeText);
        statusText = findViewById(R.id.statusText);
        balanceText = findViewById(R.id.balanceText);
        accountsBox = findViewById(R.id.accountsBox);

        client = new NodeClient(Prefs.nodeUrl(this));
        nodeText.setText("node: " + Prefs.nodeUrl(this));

        findViewById(R.id.refreshBtn).setOnClickListener(v -> refresh());
        findViewById(R.id.mineBtn).setOnClickListener(v -> mine());
        findViewById(R.id.nodeBtn).setOnClickListener(v -> editNode());
        findViewById(R.id.receiveBtn).setOnClickListener(v -> showReceive());
        findViewById(R.id.sendBtn).setOnClickListener(v -> showSend());
        findViewById(R.id.historyBtn).setOnClickListener(v -> showHistory());
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    @Override
    protected void onDestroy() {
        io.shutdownNow();
        super.onDestroy();
    }

    // ------------------------------------------------------------------ data

    private void refresh() {
        final String base = Prefs.nodeUrl(this);
        client = new NodeClient(base);
        nodeText.setText("node: " + base);
        statusText.setText("connecting...");
        io.execute(() -> {
            try {
                String statusBody = client.get("/api/status");
                String accountsBody = client.get("/api/accounts");
                JSONObject parsedStatus = new JSONObject(statusBody);
                JSONArray parsedAccounts = new JSONObject(accountsBody).getJSONArray("accounts");
                List<Account> parsed = new ArrayList<>();
                for (int i = 0; i < parsedAccounts.length(); i++) {
                    JSONObject entry = parsedAccounts.getJSONObject(i);
                    Account account = new Account();
                    account.name = entry.optString("name", "Account " + (i + 1));
                    account.address = entry.optString("address", "");
                    account.shortAddress = entry.optString("short", "");
                    account.balance = entry.optLong("balance", 0);
                    account.notes = entry.optInt("notes", 0);
                    account.spent = entry.optBoolean("spent", false);
                    parsed.add(account);
                }
                runOnUiThread(() -> apply(parsedStatus, parsed));
            } catch (Exception error) {
                runOnUiThread(() -> fail(error));
            }
        });
    }

    private void apply(JSONObject parsedStatus, List<Account> parsed) {
        status = parsedStatus;
        accounts = parsed;

        JSONObject faucet = parsedStatus.optJSONObject("faucet");
        long balance = faucet == null ? 0 : faucet.optLong("balance", 0);
        balanceText.setText(String.valueOf(balance));

        int height = parsedStatus.optInt("height", 0);
        int mempool = parsedStatus.optInt("mempool", 0);
        String backend = parsedStatus.optString("backend", "?");
        statusText.setText("connected - height " + height + " - mempool " + mempool + " - backend " + backend);

        accountsBox.removeAllViews();
        for (Account account : accounts) {
            accountsBox.addView(accountRow(account));
        }
    }

    private View accountRow(Account account) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, 10, 0, 10);

        TextView name = new TextView(this);
        name.setText(account.name + (account.spent ? "  (spent)" : ""));
        name.setTextColor(account.spent ? 0xFFF85149 : 0xFFE8EEF6);
        name.setTextSize(15);

        TextView detail = new TextView(this);
        detail.setText(account.shortAddress + "  -  " + account.balance + " over " + account.notes + " note(s)");
        detail.setTextColor(0xFF8B9BB0);
        detail.setTextSize(12);

        row.addView(name);
        row.addView(detail);
        return row;
    }

    private void fail(Exception error) {
        statusText.setText("error: " + error.getMessage());
        Toast.makeText(this, error.getMessage(), Toast.LENGTH_LONG).show();
    }

    // --------------------------------------------------------------- actions

    private void mine() {
        Toast.makeText(this, "mining...", Toast.LENGTH_SHORT).show();
        io.execute(() -> {
            try {
                String body = client.postJson("/api/mine", "{}");
                JSONObject result = new JSONObject(body);
                runOnUiThread(() -> {
                    Toast.makeText(this, "block " + result.optInt("height") + " with "
                            + result.optInt("transactions") + " tx", Toast.LENGTH_LONG).show();
                    refresh();
                });
            } catch (Exception error) {
                runOnUiThread(() -> fail(error));
            }
        });
    }

    private void editNode() {
        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        input.setText(Prefs.nodeUrl(this));
        input.setSingleLine(true);

        new AlertDialog.Builder(this)
                .setTitle("Node address")
                .setMessage("e.g. http://192.168.1.10:8642 - the node must be started with --host 0.0.0.0")
                .setView(input)
                .setPositiveButton("Save", (dialog, which) -> {
                    Prefs.setNodeUrl(this, input.getText().toString());
                    refresh();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showReceive() {
        if (accounts.isEmpty()) {
            Toast.makeText(this, "no accounts loaded yet", Toast.LENGTH_SHORT).show();
            return;
        }
        int index = firstFunded();
        Account account = accounts.get(index);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 16, 24, 0);

        ImageView qr = new ImageView(this);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(560, 560);
        params.gravity = android.view.Gravity.CENTER_HORIZONTAL;
        qr.setLayoutParams(params);
        layout.addView(qr);

        TextView heading = new TextView(this);
        heading.setText(account.name);
        heading.setTextColor(0xFFE8EEF6);
        heading.setTextSize(15);
        heading.setPadding(0, 12, 0, 4);
        layout.addView(heading);

        TextView address = new TextView(this);
        address.setText(account.address);
        address.setTextColor(0xFF8B9BB0);
        address.setTextSize(10);
        address.setTextIsSelectable(true);
        layout.addView(address);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Receive")
                .setView(scroll)
                .setPositiveButton("Close", null)
                .show();

        io.execute(() -> {
            try {
                String encoded = URLEncoder.encode(account.address, "UTF-8");
                Bitmap bitmap = client.getBitmap("/api/qr.png?text=" + encoded);
                runOnUiThread(() -> qr.setImageBitmap(bitmap));
            } catch (Exception error) {
                runOnUiThread(() -> heading.setText("QR unavailable: " + error.getMessage()));
            }
        });
        dialog.getWindow();
    }

    private int firstFunded() {
        for (int i = 0; i < accounts.size(); i++) {
            if (!accounts.get(i).spent && accounts.get(i).balance > 0) {
                return i;
            }
        }
        return 0;
    }

    private void showSend() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 8, 24, 0);

        EditText to = new EditText(this);
        to.setHint("recipient rtx1...");
        to.setSingleLine(false);
        to.setMaxLines(3);
        EditText amount = new EditText(this);
        amount.setHint("amount");
        amount.setInputType(InputType.TYPE_CLASS_NUMBER);
        amount.setText("100");
        EditText fee = new EditText(this);
        fee.setHint("fee");
        fee.setInputType(InputType.TYPE_CLASS_NUMBER);
        fee.setText("10");

        layout.addView(to);
        layout.addView(amount);
        layout.addView(fee);

        TextView note = new TextView(this);
        note.setText("Signing happens on the node and takes 1-2 minutes on the Python backend. Keep the app open.");
        note.setTextColor(0xFFD29922);
        note.setTextSize(11);
        layout.addView(note);

        new AlertDialog.Builder(this)
                .setTitle("Send")
                .setView(layout)
                .setPositiveButton("Sign and submit", (dialog, which) -> {
                    String recipient = to.getText().toString().trim();
                    int amountValue = parse(amount.getText().toString());
                    int feeValue = parse(fee.getText().toString());
                    send(recipient, amountValue, feeValue);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private static int parse(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException error) {
            return 0;
        }
    }

    private void send(String recipient, int amount, int fee) {
        if (recipient.isEmpty() || amount <= 0 || fee < 0) {
            Toast.makeText(this, "enter a recipient, a positive amount and a fee", Toast.LENGTH_LONG).show();
            return;
        }
        Toast.makeText(this, "signing on the node - this can take a minute", Toast.LENGTH_LONG).show();
        io.execute(() -> {
            try {
                JSONObject payload = new JSONObject();
                payload.put("to", recipient);
                payload.put("amount", amount);
                payload.put("fee", fee);
                String body = client.postJson("/api/send", payload.toString());
                JSONObject result = new JSONObject(body);
                runOnUiThread(() -> {
                    Toast.makeText(this, "submitted " + result.optString("id"), Toast.LENGTH_LONG).show();
                    refresh();
                });
            } catch (Exception error) {
                runOnUiThread(() -> fail(error));
            }
        });
    }

    private void showHistory() {
        io.execute(() -> {
            try {
                String body = client.get("/api/history");
                JSONArray history = new JSONObject(body).getJSONArray("history");
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < history.length(); i++) {
                    JSONObject entry = history.getJSONObject(i);
                    builder.append(entry.optString("status"))
                            .append("  ")
                            .append(entry.optString("id"))
                            .append("  value ")
                            .append(entry.optLong("value"))
                            .append("  fee ")
                            .append(entry.optLong("fee"))
                            .append('\n');
                }
                String text = builder.length() == 0 ? "no transactions yet" : builder.toString();
                runOnUiThread(() -> {
                    TextView view = new TextView(this);
                    view.setText(text);
                    view.setTextSize(12);
                    view.setTextColor(0xFFE8EEF6);
                    view.setPadding(24, 16, 24, 0);
                    ScrollView scroll = new ScrollView(this);
                    scroll.addView(view);
                    new AlertDialog.Builder(this)
                            .setTitle("History")
                            .setView(scroll)
                            .setPositiveButton("Close", null)
                            .show();
                });
            } catch (Exception error) {
                runOnUiThread(() -> fail(error));
            }
        });
    }

    @SuppressWarnings("unused")
    private void unused(ViewGroup group) {
        // keeps the import list honest if the layout changes
    }
}
