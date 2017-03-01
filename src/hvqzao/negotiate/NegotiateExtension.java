package hvqzao.negotiate;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Properties;
//import javax.swing.SwingUtilities;

public class NegotiateExtension implements IBurpExtender {

    private Properties properties;
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static PrintWriter stdout;
    private static PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        NegotiateExtension.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("Negotiate");
        //SwingUtilities.invokeLater(() -> {
        //
        //});

        test();
        
        //setup();

    }

    public static PrintWriter getStdout() {
        return stdout;
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    private void test() {
        stdout.println("[+] test started");

        //
        // get initial config
        //
        properties = new Properties();
        try {
            properties.load(NegotiateExtension.class.getResourceAsStream("/resources/test-creds.properties"));
        } catch (IOException ex) {
            ex.printStackTrace(stderr);
            return;
        }
        String targetUrl = properties.getProperty("target_url");
        //String targetHost;
        String domain = properties.getProperty("domain");
        //String realm;
        String username = properties.getProperty("username");
        String password = properties.getProperty("password");
        //String principal;

        //
        // mangle config
        //
        URL targetURL;
        try {
            targetURL = new URL(targetUrl);
        } catch (MalformedURLException ex) {
            ex.printStackTrace(stderr);
            return;
        }
        String host = targetURL.getHost();
        boolean https = targetURL.toString().trim().toLowerCase().startsWith("https://");
        int port = targetURL.getPort();
        if (port == -1) {
            if (https) {
                port = 443;
            } else {
                port = 80;
            }
        }

        //
        // unlimited JCE check
        //
        // "Due to export control restrictions, JDK 5.0 environments do not ship
        // with support for AES-256 enabled. Kerberos uses AES-256 in the
        // 'aes256-cts-hmac-sha1-96' encryption type. To enable AES-256, you
        // must download "unlimited strength" policy JAR files for your JRE.
        // Policy JAR files are signed by the JRE vendor so you must download
        // policy JAR files for Sun, IBM, etc. separately. Also, policy files
        // may be different for each platform, such as i386, Solaris, or HP."
        // Source:
        // https://cwiki.apache.org/confluence/display/DIRxSRVx10/Kerberos+and+Unlimited+Strength+Policy
        //
        boolean unlimitedJCE = Negotiate.isUnlimitedJCE();
        stdout.println(String.format("    Unlimited Strength Java(TM) Cryptography Extension Policy Files %s", unlimitedJCE ? "detected" : "missing!"));
        if (unlimitedJCE == false) {
            stdout.println("[ ] Negotiate authentication might not work!");
        }

        //
        // login, get ticket and test Negotiate authentication
        //
        Negotiate negotiate = new Negotiate(domain, username, password, true, true, true);
        if (negotiate.login()) {
            stdout.println("[+] login successful");
        } else {
            stdout.println("[ ] login failed");
            return;
        }
        String ticket = negotiate.getTicket(targetURL);
        if (ticket == null) {
            stdout.println("[ ] failed to obtain a ticket");
        }

        //
        // base request (no authentication)
        //
        byte[] baseRequest = helpers.buildHttpRequest(targetURL);
        byte[] baseResponse = callbacks.makeHttpRequest(host, port, https, baseRequest);
        IResponseInfo baseResponseInfo = helpers.analyzeResponse(baseResponse);
        stdout.println("[+] base response - status code: " + String.valueOf(baseResponseInfo.getStatusCode()));
        //
        // HTTP/1.1 401 Unauthorized
        // www-authenticate: NegotiateExtension
        //
        // Authorization: NegotiateExtension YII[...]
        //
        // fiddler's ticket length: 4972
        // generated ticket length: 6320 (SPNEGO), 6256 (KRB_5)

        //
        // auth request (with authentication)
        //
        IRequestInfo baseRequestInfo = helpers.analyzeRequest(baseRequest);
        List<String> headers = baseRequestInfo.getHeaders();
        headers.add("Authorization: Negotiate " + ticket);
        byte[] authRequest = helpers.buildHttpMessage(headers, new byte[0]);
        byte[] authResponse = callbacks.makeHttpRequest(host, port, https, authRequest);
        IResponseInfo authResponseInfo = helpers.analyzeResponse(authResponse);
        stdout.println("[+] auth response - status code: " + String.valueOf(authResponseInfo.getStatusCode()));

        negotiate.logout();
        stdout.println("[+] test completed");
    }

    void setup() {
        //
        // get initial config
        //
        properties = new Properties();
        try {
            properties.load(NegotiateExtension.class.getResourceAsStream("/resources/test-creds.properties"));
        } catch (IOException ex) {
            ex.printStackTrace(stderr);
            return;
        }
        String scopeUrl = properties.getProperty("scope_url");
        //String targetHost;
        String domain = properties.getProperty("domain");
        //String realm;
        String username = properties.getProperty("username");
        String password = properties.getProperty("password");
        //String principal;

        //
        // mangle config
        //
        URL scopeURL;
        try {
            scopeURL = new URL(scopeUrl);
        } catch (MalformedURLException ex) {
            ex.printStackTrace(stderr);
            return;
        }

        //
        // we don't use burp scope
        //
        //callbacks.includeInScope(scopeURL);

        Negotiate negotiate = new Negotiate(domain, username, password, true, true, true);
        if (negotiate.login() == false) {
            stdout.println("login failed!");
            return;
        }
        negotiate.scopeAdd(scopeURL);
        callbacks.registerHttpListener(negotiate);
        
        //
        // TODO
        //
        // [ ]    ProcessErrorTokenResponse
        // [ ]    processHttpMessage
        //
    }
}
