package burp;

import java.util.List;

/** Compile-time stub. */
public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(IHttpRequestResponse message);

    IRequestInfo analyzeRequest(byte[] request);

    IResponseInfo analyzeResponse(byte[] response);

    String bytesToString(byte[] data);

    byte[] buildHttpMessage(List<String> headers, byte[] body);
}
