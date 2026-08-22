package burp;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CipherBridge Burp 扩展：
 * 1) 上游代理（密桥启动加密时自动设置）
 * 2) 流量表 + 右键发送到密桥 AI 分析
 * 加解密仍走密桥本地 mitm 插件，不在 Burp 内加载配置。
 */
public class BurpExtender implements IBurpExtender, IExtensionStateListener, ITab,
        IContextMenuFactory {

    public static final int DEFAULT_PORT = 19527;
    public static final int CIPHERBRIDGE_INBOX_PORT = 19528;
    public static final String EXT_NAME = "CipherBridge Upstream";
    public static final String TAB_NAME = "CipherBridge";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HttpServer server;
    private String savedUpstreamJson;
    private volatile String lastStatus = "idle";

    private JPanel rootPanel;
    private JLabel apiStatusLabel;
    private JLabel upstreamStatusLabel;
    private JTextField hostField;
    private JSpinner portSpinner;
    private JTextArea logArea;
    private DefaultTableModel trafficModel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXT_NAME);
        callbacks.registerExtensionStateListener(this);
        callbacks.registerContextMenuFactory(this);

        try {
            SwingUtilities.invokeAndWait(() -> {
                buildUi();
                callbacks.addSuiteTab(this);
                appendLog("扩展已加载 → 顶部页签「" + TAB_NAME + "」");
                appendLog("右键流量：发送到密桥");
            });
        } catch (Exception e) {
            callbacks.printError("UI init failed: " + e.getMessage());
        }

        try {
            startServer(DEFAULT_PORT);
            callbacks.printOutput(EXT_NAME + " ready — http://127.0.0.1:" + DEFAULT_PORT);
            appendLog("上游 API: http://127.0.0.1:" + DEFAULT_PORT);
            appendLog("推送密桥: http://127.0.0.1:" + CIPHERBRIDGE_INBOX_PORT + "/flows");
            setApiStatusUi("API 监听中 · 127.0.0.1:" + DEFAULT_PORT);
        } catch (Exception e) {
            callbacks.printError("Failed to start local API: " + e.getMessage());
            appendLog("API 启动失败: " + e.getMessage());
            setApiStatusUi("API 启动失败");
        }
    }

    @Override
    public void extensionUnloaded() {
        stopServer();
        callbacks.printOutput(EXT_NAME + " unloaded");
    }

    @Override
    public String getTabCaption() {
        return TAB_NAME;
    }

    @Override
    public Component getUiComponent() {
        return rootPanel;
    }

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(8, 8));
        rootPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("上游代理", buildUpstreamPanel());
        tabs.addTab("流量", buildTrafficPanel());
        rootPanel.add(tabs, BorderLayout.CENTER);

        logArea = new JTextArea(6, 60);
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(logArea);
        scroll.setBorder(BorderFactory.createTitledBorder("日志"));
        rootPanel.add(scroll, BorderLayout.SOUTH);
    }

    private JPanel buildUpstreamPanel() {
        JPanel top = new JPanel(new GridBagLayout());
        top.setBorder(BorderFactory.createTitledBorder("密桥 · Burp 上游代理"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;

        c.gridx = 0; c.gridy = 0; c.weightx = 0;
        top.add(new JLabel("API 状态:"), c);
        apiStatusLabel = new JLabel("初始化…");
        c.gridx = 1; c.weightx = 1;
        top.add(apiStatusLabel, c);

        c.gridx = 0; c.gridy = 1; c.weightx = 0;
        top.add(new JLabel("上游状态:"), c);
        upstreamStatusLabel = new JLabel("未设置");
        c.gridx = 1; c.weightx = 1;
        top.add(upstreamStatusLabel, c);

        c.gridx = 0; c.gridy = 2; c.weightx = 0;
        top.add(new JLabel("代理 Host:"), c);
        hostField = new JTextField("127.0.0.1");
        c.gridx = 1; c.weightx = 1;
        top.add(hostField, c);

        c.gridx = 0; c.gridy = 3; c.weightx = 0;
        top.add(new JLabel("代理 Port:"), c);
        portSpinner = new JSpinner(new SpinnerNumberModel(8081, 1, 65535, 1));
        c.gridx = 1; c.weightx = 0;
        top.add(portSpinner, c);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton setBtn = new JButton("设为上游");
        setBtn.addActionListener(e -> {
            String host = hostField.getText().trim();
            if (host.isEmpty()) host = "127.0.0.1";
            int port = ((Number) portSpinner.getValue()).intValue();
            try {
                setUpstream(host, port);
                lastStatus = "upstream=" + host + ":" + port;
                setUpstreamStatusUi("已设置 → " + host + ":" + port);
                appendLog("手动设置上游 → " + host + ":" + port);
                addTrafficRow("UPSTREAM", "SET", host + ":" + port, "-");
            } catch (Exception ex) {
                appendLog("设置失败: " + ex.getMessage());
            }
        });
        JButton clearBtn = new JButton("恢复/清除上游");
        clearBtn.addActionListener(e -> {
            try {
                clearUpstream();
                lastStatus = "cleared";
                setUpstreamStatusUi("已恢复/清除");
                appendLog("已恢复/清除上游代理");
                addTrafficRow("UPSTREAM", "CLEAR", "-", "-");
            } catch (Exception ex) {
                appendLog("清除失败: " + ex.getMessage());
            }
        });
        btns.add(setBtn);
        btns.add(clearBtn);
        c.gridx = 0; c.gridy = 4; c.gridwidth = 2; c.weightx = 1;
        top.add(btns, c);

        JLabel tip = new JLabel("<html>拓扑：浏览器→解密→Burp→加密→服务器。"
                + "密桥点「启动加密」会自动把上游设到加密端口。</html>");
        c.gridx = 0; c.gridy = 5; c.gridwidth = 2;
        top.add(tip, c);

        JPanel wrap = new JPanel(new BorderLayout());
        wrap.add(top, BorderLayout.NORTH);
        return wrap;
    }

    private JPanel buildTrafficPanel() {
        trafficModel = new DefaultTableModel(
                new Object[]{"时间", "动作", "方法", "URL/详情", "结果"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(trafficModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.getColumnModel().getColumn(0).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(90);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);
        table.getColumnModel().getColumn(3).setPreferredWidth(360);
        table.getColumnModel().getColumn(4).setPreferredWidth(120);

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clear = new JButton("清空列表");
        clear.addActionListener(e -> trafficModel.setRowCount(0));
        bar.add(clear);
        bar.add(new JLabel("显示：发送到密桥 / 上游变更"));

        JPanel wrap = new JPanel(new BorderLayout(6, 6));
        wrap.add(bar, BorderLayout.NORTH);
        wrap.add(new JScrollPane(table), BorderLayout.CENTER);
        return wrap;
    }

    // ---- traffic / log helpers ----

    private void addTrafficRow(final String action, final String method, final String url, final String result) {
        final String ts = new SimpleDateFormat("HH:mm:ss").format(new Date());
        Runnable r = () -> {
            if (trafficModel == null) return;
            String u = url == null ? "" : url;
            if (u.length() > 180) u = u.substring(0, 180) + "…";
            trafficModel.insertRow(0, new Object[]{ts, action, method, u, result});
            while (trafficModel.getRowCount() > 500) {
                trafficModel.removeRow(trafficModel.getRowCount() - 1);
            }
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    // ---- context menu ----

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        List<JMenuItem> items = new ArrayList<JMenuItem>();
        if (messages == null || messages.length == 0) {
            return items;
        }
        JMenuItem send = new JMenuItem("发送到密桥 · AI分析/网页流量 (" + messages.length + ")");
        send.addActionListener(e -> new Thread(() -> sendSelectedToCipherBridge(messages),
                "cb-send-flows").start());
        items.add(send);
        return items;
    }

    // ---- send to CipherBridge GUI ----

    private void sendSelectedToCipherBridge(IHttpRequestResponse[] messages) {
        try {
            StringBuilder arr = new StringBuilder();
            arr.append("{\"flows\":[");
            int n = 0;
            for (IHttpRequestResponse msg : messages) {
                if (msg == null || msg.getRequest() == null) continue;
                String one = flowToJson(msg);
                if (one == null) continue;
                if (n > 0) arr.append(',');
                arr.append(one);
                n++;
                if (n >= 50) break;
            }
            arr.append("]}");
            if (n == 0) {
                appendLogUi("没有可发送的请求");
                return;
            }
            String resp = httpPostJson(
                    "http://127.0.0.1:" + CIPHERBRIDGE_INBOX_PORT + "/flows", arr.toString());
            appendLogUi("已发送 " + n + " 条到密桥 → " + resp);
            for (IHttpRequestResponse msg : messages) {
                try {
                    IRequestInfo info = helpers.analyzeRequest(msg);
                    addTrafficRow("SEND→密桥", info.getMethod(), String.valueOf(info.getUrl()), "ok");
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ex) {
            String err = ex.getMessage() == null ? ex.toString() : ex.getMessage();
            appendLogUi("发送失败（请先打开密桥）: " + err);
            addTrafficRow("SEND→密桥", "-", "-", "FAIL");
        }
    }

    private String flowToJson(IHttpRequestResponse msg) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(msg);
            byte[] req = msg.getRequest();
            int bodyOff = reqInfo.getBodyOffset();
            String body = "";
            if (req != null && bodyOff >= 0 && bodyOff < req.length) {
                body = helpers.bytesToString(Arrays.copyOfRange(req, bodyOff, req.length));
            }
            String method = reqInfo.getMethod();
            URL u = reqInfo.getUrl();
            String url = u != null ? u.toString() : "";
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            sb.append("\"method\":\"").append(escapeJson(method)).append("\",");
            sb.append("\"url\":\"").append(escapeJson(url)).append("\",");
            sb.append("\"request_headers\":");
            appendHeaderArray(sb, reqInfo.getHeaders());
            sb.append(',');
            sb.append("\"request_body\":\"").append(escapeJson(body)).append("\",");
            byte[] resp = msg.getResponse();
            int status = 0;
            String respBody = "";
            if (resp != null && resp.length > 0) {
                IResponseInfo respInfo = helpers.analyzeResponse(resp);
                status = respInfo.getStatusCode();
                int rOff = respInfo.getBodyOffset();
                if (rOff >= 0 && rOff < resp.length) {
                    respBody = helpers.bytesToString(Arrays.copyOfRange(resp, rOff, resp.length));
                }
                sb.append("\"response_headers\":");
                appendHeaderArray(sb, respInfo.getHeaders());
                sb.append(',');
            } else {
                sb.append("\"response_headers\":[],");
            }
            sb.append("\"response_body\":\"").append(escapeJson(respBody)).append("\",");
            sb.append("\"status\":").append(status).append(',');
            sb.append("\"source\":\"burp\"");
            sb.append('}');
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static void appendHeaderArray(StringBuilder sb, List<String> headers) {
        sb.append('[');
        if (headers != null) {
            boolean first = true;
            for (int i = 0; i < headers.size(); i++) {
                String line = headers.get(i);
                if (line == null) continue;
                if (i == 0 && (line.startsWith("HTTP/") || line.contains(" HTTP/"))) continue;
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(escapeJson(line)).append('"');
            }
        }
        sb.append(']');
    }

    // ---- upstream HTTP API (same as before) ----

    private void startServer(int port) throws IOException {
        stopServer();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/health", this::handleHealth);
        server.createContext("/upstream/clear", this::handleClear);
        server.createContext("/upstream", this::handleUpstream);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    private void stopServer() {
        if (server != null) {
            try { server.stop(0); } catch (Exception ignored) {}
            server = null;
        }
    }

    private void handleHealth(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())
                && !"HEAD".equalsIgnoreCase(ex.getRequestMethod())) {
            sendJson(ex, 405, "{\"ok\":false,\"error\":\"method not allowed\"}");
            return;
        }
        String body = "{\"ok\":true,\"extension\":\"" + EXT_NAME + "\","
                + "\"tab\":\"" + TAB_NAME + "\","
                + "\"port\":" + DEFAULT_PORT + ","
                + "\"inbox\":" + CIPHERBRIDGE_INBOX_PORT + ","
                + "\"status\":\"" + escapeJson(lastStatus) + "\"}";
        sendJson(ex, 200, body);
    }

    private void handleClear(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())
                && !"DELETE".equalsIgnoreCase(ex.getRequestMethod())) {
            sendJson(ex, 405, "{\"ok\":false,\"error\":\"method not allowed\"}");
            return;
        }
        try {
            clearUpstream();
            lastStatus = "cleared";
            setUpstreamStatusUi("已恢复/清除（来自密桥）");
            appendLogUi("密桥请求：恢复/清除上游");
            addTrafficRow("UPSTREAM", "CLEAR", "from-密桥", "ok");
            sendJson(ex, 200, "{\"ok\":true,\"action\":\"clear\"}");
        } catch (Exception e) {
            sendJson(ex, 500, "{\"ok\":false,\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
        }
    }

    private void handleUpstream(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        if (path != null && path.endsWith("/clear")) {
            handleClear(ex);
            return;
        }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())
                && !"PUT".equalsIgnoreCase(ex.getRequestMethod())) {
            sendJson(ex, 405, "{\"ok\":false,\"error\":\"method not allowed\"}");
            return;
        }
        String body = readBody(ex);
        String host = extractString(body, "host");
        if (host == null || host.isEmpty()) host = "127.0.0.1";
        Integer port = extractInt(body, "port");
        if (port == null) port = extractIntFromQuery(ex.getRequestURI().getRawQuery(), "port");
        if (port == null || port <= 0 || port > 65535) {
            sendJson(ex, 400, "{\"ok\":false,\"error\":\"port required (1-65535)\"}");
            return;
        }
        try {
            setUpstream(host, port);
            lastStatus = "upstream=" + host + ":" + port;
            final String h = host;
            final int p = port;
            setUpstreamStatusUi("已设置 → " + h + ":" + p + "（来自密桥）");
            appendLogUi("密桥请求：上游 → " + h + ":" + p);
            addTrafficRow("UPSTREAM", "SET", h + ":" + p, "from-密桥");
            SwingUtilities.invokeLater(() -> {
                if (hostField != null) hostField.setText(h);
                if (portSpinner != null) portSpinner.setValue(p);
            });
            sendJson(ex, 200, "{\"ok\":true,\"action\":\"set\",\"host\":\"" + escapeJson(host)
                    + "\",\"port\":" + port + "}");
        } catch (Exception e) {
            sendJson(ex, 500, "{\"ok\":false,\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
        }
    }

    private synchronized void setUpstream(String host, int port) {
        if (savedUpstreamJson == null) {
            try {
                savedUpstreamJson = callbacks.saveConfigAsJson(
                        "project_options.connections.upstream_proxy");
            } catch (Exception e) {
                savedUpstreamJson = "";
            }
        }
        callbacks.loadConfigFromJson(buildUpstreamConfig(host, port));
    }

    private synchronized void clearUpstream() {
        if (savedUpstreamJson != null && !savedUpstreamJson.trim().isEmpty()) {
            callbacks.loadConfigFromJson(savedUpstreamJson);
            savedUpstreamJson = null;
            return;
        }
        callbacks.loadConfigFromJson(buildEmptyUpstreamConfig());
        savedUpstreamJson = null;
    }

    private static String buildUpstreamConfig(String host, int port) {
        return "{\"project_options\":{\"connections\":{\"upstream_proxy\":{\"servers\":[{"
                + "\"enabled\":true,\"destination_host\":\"*\","
                + "\"proxy_host\":\"" + escapeJson(host) + "\",\"proxy_port\":" + port
                + "}]}}}}";
    }

    private static String buildEmptyUpstreamConfig() {
        return "{\"project_options\":{\"connections\":{\"upstream_proxy\":{\"servers\":[]}}}}";
    }

    private void appendLog(String line) { appendLogUi(line); }

    private void appendLogUi(final String line) {
        final String ts = new SimpleDateFormat("HH:mm:ss").format(new Date());
        final String msg = "[" + ts + "] " + line;
        Runnable r = () -> {
            if (logArea == null) return;
            logArea.append(msg + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    private void setApiStatusUi(final String text) {
        Runnable r = () -> { if (apiStatusLabel != null) apiStatusLabel.setText(text); };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    private void setUpstreamStatusUi(final String text) {
        Runnable r = () -> { if (upstreamStatusLabel != null) upstreamStatusLabel.setText(text); };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    private static void sendJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", "application/json; charset=utf-8");
        h.set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, data.length);
        OutputStream os = ex.getResponseBody();
        os.write(data);
        os.close();
    }

    private static String readBody(HttpExchange ex) throws IOException {
        InputStream in = ex.getRequestBody();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = in.read(tmp)) >= 0) buf.write(tmp, 0, n);
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String httpPostJson(String url, String json) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(8000);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        conn.setRequestProperty("Content-Length", String.valueOf(data.length));
        OutputStream os = conn.getOutputStream();
        os.write(data);
        os.close();
        int code = conn.getResponseCode();
        InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String body = "";
        if (in != null) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = in.read(tmp)) >= 0) buf.write(tmp, 0, n);
            in.close();
            body = new String(buf.toByteArray(), StandardCharsets.UTF_8);
        }
        if (code >= 400) throw new IOException("HTTP " + code + " " + body);
        return body;
    }

    private static String extractString(String json, String key) {
        if (json == null) return null;
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static Integer extractInt(String json, String key) {
        if (json == null) return null;
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)");
        Matcher m = p.matcher(json);
        if (!m.find()) return null;
        try { return Integer.parseInt(m.group(1)); } catch (Exception e) { return null; }
    }

    private static Integer extractIntFromQuery(String query, String key) {
        if (query == null || query.isEmpty()) return null;
        for (String part : query.split("&")) {
            int i = part.indexOf('=');
            if (i <= 0) continue;
            if (key.equals(part.substring(0, i))) {
                try { return Integer.parseInt(part.substring(i + 1)); }
                catch (Exception e) { return null; }
            }
        }
        return null;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        return sb.toString();
    }
}
