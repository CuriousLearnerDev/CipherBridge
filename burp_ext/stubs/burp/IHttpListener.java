package burp;

/** Compile-time stub. */
public interface IHttpListener {
    void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo);
}
