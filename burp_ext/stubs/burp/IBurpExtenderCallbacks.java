package burp;

/** Compile-time stub — Burp provides the real class at runtime. */
public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);

    void printOutput(String message);

    void printError(String message);

    void registerExtensionStateListener(IExtensionStateListener listener);

    void addSuiteTab(ITab tab);

    void registerContextMenuFactory(IContextMenuFactory factory);

    void registerHttpListener(IHttpListener listener);

    IExtensionHelpers getHelpers();

    /**
     * Persist a temporary request/response so it remains valid after the
     * context-menu callback returns (required before background send).
     */
    IHttpRequestResponse saveBuffersToTempFiles(IHttpRequestResponse requestResponse);

    String saveConfigAsJson(String... paths);

    void loadConfigFromJson(String config);
}
