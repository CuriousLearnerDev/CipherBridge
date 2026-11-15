package burp;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenu;
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
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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
    private JButton pushBtn;

    /**
     * 待推送队列用静态列表：Burp Reload 后可能短暂存在多个 Extender 实例，
     * 右键回调与页签按钮若落在不同实例上，实例字段会“加入成功但推送为空”。
     */
    private static final List<HeldMessage> PENDING_PUSH =
            Collections.synchronizedList(new ArrayList<HeldMessage>());

    /** 右键瞬间拷贝的请求/响应，避免临时对象在点击后失效. */
    private static final class HeldMessage {
        final byte[] request;
        final byte[] response;
        final String host;
        final int port;
        final String protocol;

        HeldMessage(byte[] request, byte[] response, String host, int port, String protocol) {
            this.request = request;
            this.response = response;
            this.host = host == null ? "" : host;
            this.port = port;
            this.protocol = protocol == null || protocol.isEmpty() ? "https" : protocol;
        }
    }

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
                appendLog("用法：Proxy→HTTP history 先选中行 → 右键找「密桥 CipherBridge」");
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
        clear.addActionListener(e -> {
            trafficModel.setRowCount(0);
            PENDING_PUSH.clear();
            refreshPushBtn();
            appendLogUi("已清空扩展列表 / 待推送队列");
        });
        JButton ping = new JButton("测试密桥连接");
        ping.setToolTipText("直连 127.0.0.1:" + CIPHERBRIDGE_INBOX_PORT + "（不走 Burp 上游代理）");
        ping.addActionListener(e -> new Thread(this::pingCipherBridgeInbox, "cb-ping-inbox").start());
        pushBtn = new JButton("推送列表到密桥 (0)");
        pushBtn.setToolTipText("把右键「先加入扩展列表」的流量推送到密桥 AI 分析");
        pushBtn.addActionListener(e -> new Thread(this::pushPendingToCipherBridge, "cb-push-pending").start());
        bar.add(clear);
        bar.add(ping);
        bar.add(pushBtn);
        bar.add(new JLabel("推荐直接右键「发送到密桥」"));
        refreshPushBtn();

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
        List<JMenuItem> items = new ArrayList<JMenuItem>();
        try {
            IHttpRequestResponse[] selected = invocation.getSelectedMessages();
            if (selected == null || selected.length == 0) {
                // 没选中行时不显示；用户需先点选 Proxy History 中的条目
                return items;
            }

            // 在 createMenuItems 返回前立刻拷贝字节（此时对象仍有效）
            final HeldMessage[] held = snapshotMessages(selected);
            if (held.length == 0) {
                callbacks.printOutput("CipherBridge: selected "
                        + selected.length + " but snapshot empty");
                return items;
            }

            JMenu menu = new JMenu("密桥 CipherBridge");
            JMenuItem send = new JMenuItem("发送到密桥 · AI分析 (" + held.length + ")");
            send.addActionListener(e -> new Thread(() -> {
                appendLogUi("右键发送 " + held.length + " 条…");
                boolean ok = sendHeldToCipherBridge(held);
                appendLogUi(ok ? "右键发送完成" : "右键发送失败");
            }, "cb-send-flows").start());
            menu.add(send);

            JMenuItem addOnly = new JMenuItem("先加入扩展列表 (" + held.length + ")");
            addOnly.addActionListener(e -> new Thread(
                    () -> addHeldToPluginList(held),
                    "cb-add-flows").start());
            menu.add(addOnly);

            items.add(menu);
            callbacks.printOutput("CipherBridge: context menu ready (" + held.length + ")");
        } catch (Exception ex) {
            String err = ex.getMessage() == null ? ex.toString() : ex.getMessage();
            appendLogUi("创建右键菜单失败: " + err);
            callbacks.printError("CipherBridge context menu: " + err);
        }
        return items;
    }

    /** 立即深拷贝选中流量，供菜单点击后使用. */
    private HeldMessage[] snapshotMessages(IHttpRequestResponse[] selected) {
        List<HeldMessage> list = new ArrayList<HeldMessage>();
        for (IHttpRequestResponse msg : selected) {
            if (msg == null) continue;
            byte[] req;
            try {
                req = msg.getRequest();
            } catch (Exception e) {
                continue;
            }
            if (req == null || req.length == 0) continue;
            byte[] reqCopy = Arrays.copyOf(req, req.length);
            byte[] respCopy = null;
            try {
                byte[] resp = msg.getResponse();
                if (resp != null && resp.length > 0) {
                    respCopy = Arrays.copyOf(resp, resp.length);
                }
            } catch (Exception ignored) {
            }
            String host = "";
            int port = 443;
            String protocol = "https";
            try {
                IHttpService svc = msg.getHttpService();
                if (svc != null) {
                    host = svc.getHost();
                    port = svc.getPort();
                    protocol = svc.getProtocol();
                }
            } catch (Exception ignored) {
            }
            // 无 service 时从 Host 头推断
            if (host == null || host.isEmpty()) {
                try {
                    IRequestInfo info = helpers.analyzeRequest(reqCopy);
                    for (String line : info.getHeaders()) {
                        if (line != null && line.regionMatches(true, 0, "Host:", 0, 5)) {
                            host = line.substring(5).trim();
                            if (host.contains(":")) {
                                int idx = host.lastIndexOf(':');
                                try {
                                    port = Integer.parseInt(host.substring(idx + 1).trim());
                                } catch (Exception ignored) {
                                }
                                host = host.substring(0, idx).trim();
                            }
                            break;
                        }
                    }
                } catch (Exception ignored) {
                }
            }
            list.add(new HeldMessage(reqCopy, respCopy, host, port, protocol));
            if (list.size() >= 50) break;
        }
        return list.toArray(new HeldMessage[0]);
    }

    private void refreshPushBtn() {
        final int n = PENDING_PUSH.size();
        Runnable r = () -> {
            if (pushBtn != null) {
                pushBtn.setText("推送列表到密桥 (" + n + ")");
            }
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    private void addHeldToPluginList(HeldMessage[] held) {
        int n = 0;
        List<HeldMessage> added = new ArrayList<HeldMessage>();
        for (HeldMessage msg : held) {
            if (msg == null || msg.request == null) continue;
            try {
                IRequestInfo info = helpers.analyzeRequest(msg.request);
                String url = buildUrl(msg, info);
                addTrafficRow("已加入列表", info.getMethod(), url, "pending");
                added.add(msg);
                n++;
            } catch (Exception ex) {
                addTrafficRow("已加入列表", "-", "-", "skip");
            }
        }
        synchronized (PENDING_PUSH) {
            PENDING_PUSH.addAll(added);
            while (PENDING_PUSH.size() > 200) {
                PENDING_PUSH.remove(0);
            }
        }
        refreshPushBtn();
        appendLogUi("已加入扩展列表 " + n + " 条，待推送队列=" + PENDING_PUSH.size()
                + "。也可直接右键用「发送到密桥」。");
    }

    private void pushPendingToCipherBridge() {
        HeldMessage[] msgs;
        synchronized (PENDING_PUSH) {
            if (PENDING_PUSH.isEmpty()) {
                appendLogUi("待推送队列为空 (0)。请右键 → 密桥 CipherBridge →「发送到密桥」或「先加入扩展列表」。");
                refreshPushBtn();
                return;
            }
            msgs = PENDING_PUSH.toArray(new HeldMessage[0]);
            // 先取出再发；成功后再清。失败则放回，避免“点了就丢”。
        }
        appendLogUi("开始推送 " + msgs.length + " 条到密桥…");
        boolean ok = sendHeldToCipherBridge(msgs);
        if (ok) {
            synchronized (PENDING_PUSH) {
                PENDING_PUSH.removeAll(Arrays.asList(msgs));
            }
            refreshPushBtn();
            appendLogUi("推送完成，剩余待推送=" + PENDING_PUSH.size());
        } else {
            appendLogUi("推送失败，队列仍保留 " + PENDING_PUSH.size() + " 条，可重试");
            refreshPushBtn();
        }
    }

    private void pingCipherBridgeInbox() {
        try {
            String body = httpGet(
                    "http://127.0.0.1:" + CIPHERBRIDGE_INBOX_PORT + "/health");
            appendLogUi("密桥收件箱 OK → " + body);
            addTrafficRow("PING密桥", "GET", "127.0.0.1:" + CIPHERBRIDGE_INBOX_PORT, "ok");
        } catch (Exception ex) {
            String err = ex.getMessage() == null ? ex.toString() : ex.getMessage();
            appendLogUi("密桥收件箱不可达（请先打开密桥 GUI）: " + err);
            addTrafficRow("PING密桥", "GET", "127.0.0.1:" + CIPHERBRIDGE_INBOX_PORT, "FAIL");
        }
    }

    private boolean sendHeldToCipherBridge(HeldMessage[] messages) {
        try {
            StringBuilder arr = new StringBuilder();
            arr.append("{\"flows\":[");
            int n = 0;
            int skipped = 0;
            for (HeldMessage msg : messages) {
                if (msg == null || msg.request == null) {
                    skipped++;
                    continue;
                }
                String one = heldToJson(msg);
                if (one == null) {
                    skipped++;
                    continue;
                }
                if (n > 0) arr.append(',');
                arr.append(one);
                n++;
                if (n >= 50) break;
            }
            arr.append("]}");
            if (n == 0) {
                appendLogUi("没有可发送的请求（解析失败）。请重新在 Proxy History 选中后右键。"
                        + (skipped > 0 ? " skipped=" + skipped : ""));
                addTrafficRow("SEND→密桥", "-", "-", "empty");
                return false;
            }
            String resp = httpPostJson(
                    "http://127.0.0.1:" + CIPHERBRIDGE_INBOX_PORT + "/flows", arr.toString());
            appendLogUi("已发送 " + n + " 条到密桥 → " + resp
                    + (skipped > 0 ? "（跳过 " + skipped + "）" : ""));
            int logged = 0;
            for (HeldMessage msg : messages) {
                if (logged >= n) break;
                try {
                    if (msg == null || msg.request == null) continue;
                    IRequestInfo info = helpers.analyzeRequest(msg.request);
                    addTrafficRow("SEND→密桥", info.getMethod(), buildUrl(msg, info), "ok");
                    logged++;
                } catch (Exception ignored) {
                }
            }
            return true;
        } catch (Exception ex) {
            String err = ex.getMessage() == null ? ex.toString() : ex.getMessage();
            appendLogUi("发送失败（请先打开密桥；且扩展已直连收件箱）: " + err);
            addTrafficRow("SEND→密桥", "-", "-", "FAIL");
            return false;
        }
    }

    private String buildUrl(HeldMessage msg, IRequestInfo info) {
        String path = "/";
        try {
            List<String> headers = info.getHeaders();
            if (headers != null && !headers.isEmpty()) {
                String line = headers.get(0);
                if (line != null) {
                    String[] parts = line.split(" ");
                    if (parts.length >= 2) path = parts[1];
                }
            }
        } catch (Exception ignored) {
        }
        String host = msg.host;
        if (host == null || host.isEmpty()) host = "unknown";
        int port = msg.port;
        String protocol = msg.protocol;
        boolean defaultPort = ("http".equalsIgnoreCase(protocol) && port == 80)
                || ("https".equalsIgnoreCase(protocol) && port == 443);
        if (defaultPort) {
            return protocol + "://" + host + path;
        }
        return protocol + "://" + host + ":" + port + path;
    }

    private String heldToJson(HeldMessage msg) {
        try {
            byte[] req = msg.request;
            IRequestInfo reqInfo = helpers.analyzeRequest(req);
            int bodyOff = reqInfo.getBodyOffset();
            String body = "";
            if (bodyOff >= 0 && bodyOff < req.length) {
                body = helpers.bytesToString(Arrays.copyOfRange(req, bodyOff, req.length));
            }
            String method = reqInfo.getMethod();
            String url = buildUrl(msg, reqInfo);

            int status = 0;
            String respBody = "";
            IResponseInfo respInfo = null;
            if (msg.response != null && msg.response.length > 0) {
                respInfo = helpers.analyzeResponse(msg.response);
                status = respInfo.getStatusCode();
                int rOff = respInfo.getBodyOffset();
                if (rOff >= 0 && rOff < msg.response.length) {
                    respBody = helpers.bytesToString(
                            Arrays.copyOfRange(msg.response, rOff, msg.response.length));
                }
            }

            body = truncateForSend(body, 262144);
            respBody = truncateForSend(respBody, 262144);

            StringBuilder sb = new StringBuilder();
            sb.append('{');
            sb.append("\"method\":\"").append(escapeJson(method)).append("\",");
            sb.append("\"url\":\"").append(escapeJson(url)).append("\",");
            sb.append("\"request_headers\":");
            appendHeaderArray(sb, reqInfo.getHeaders());
            sb.append(',');
            sb.append("\"request_body\":\"").append(escapeJson(body)).append("\",");
            if (respInfo != null) {
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
            callbacks.printError("heldToJson: " + e.getMessage());
            return null;
        }
    }

    private static String truncateForSend(String s, int maxChars) {
        if (s == null) return "";
        if (s.length() <= maxChars) return s;
        return s.substring(0, maxChars) + "\n/* truncated by CipherBridge burp ext */";
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

    /** 直连本机，绝不走 Burp/系统 HTTP 代理（否则上游加密端会劫持发往密桥的请求）。 */
    private static HttpURLConnection openDirect(String url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection(Proxy.NO_PROXY);
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(15000);
        conn.setInstanceFollowRedirects(false);
        conn.setUseCaches(false);
        return conn;
    }

    private static String readConnBody(HttpURLConnection conn, int code) throws IOException {
        InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (in == null) return "";
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = in.read(tmp)) >= 0) buf.write(tmp, 0, n);
        in.close();
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String httpGet(String url) throws IOException {
        HttpURLConnection conn = openDirect(url);
        conn.setRequestMethod("GET");
        int code = conn.getResponseCode();
        String body = readConnBody(conn, code);
        if (code >= 400) throw new IOException("HTTP " + code + " " + body);
        return body;
    }

    private static String httpPostJson(String url, String json) throws IOException {
        HttpURLConnection conn = openDirect(url);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        conn.setRequestProperty("Content-Length", String.valueOf(data.length));
        OutputStream os = conn.getOutputStream();
        os.write(data);
        os.close();
        int code = conn.getResponseCode();
        String body = readConnBody(conn, code);
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
