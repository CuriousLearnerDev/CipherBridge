package burp;

import java.net.URL;
import java.util.List;

/** Compile-time stub. */
public interface IRequestInfo {
    String getMethod();

    URL getUrl();

    List<String> getHeaders();

    int getBodyOffset();
}
