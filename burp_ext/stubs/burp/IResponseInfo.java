package burp;

import java.util.List;

/** Compile-time stub. */
public interface IResponseInfo {
    int getStatusCode();

    List<String> getHeaders();

    int getBodyOffset();
}
