package burp;

/** Compile-time stub. */
public interface IHttpRequestResponse {
    byte[] getRequest();

    void setRequest(byte[] message);

    byte[] getResponse();

    void setResponse(byte[] message);

    IHttpService getHttpService();
}
