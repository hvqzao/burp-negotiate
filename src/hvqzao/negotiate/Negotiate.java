package hvqzao.negotiate;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.sun.security.jgss.ExtendedGSSContext;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import org.ietf.jgss.GSSManager;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
//import javax.swing.SwingUtilities;

public class Negotiate implements IBurpExtender {

    private Properties properties;
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private final GSSManager manager = GSSManager.getInstance();
    private final Object lock = new Object();
    private final HashMap<String, ContextToken> spnContextToken = new HashMap<>();
    private final HashMap<String, String> domainSpn = new HashMap<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Negotiate.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("Negotiate");
        //SwingUtilities.invokeLater(() -> {
        //
        //});
        initialize();
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    public static boolean isUnlimitedJCE() {
        boolean unlimited = false;
        try {
            unlimited = Cipher.getMaxAllowedKeyLength("RC5") >= 256;
        } catch (NoSuchAlgorithmException ex) {
            // do nothing
        }
        return unlimited;
    }

    private class KerberosCallBackHandler implements CallbackHandler {

        private final String principal;
        private final String password;

        public KerberosCallBackHandler(String principal, String password) {
            this.principal = principal;
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            Arrays.asList(callbacks).forEach((Callback callback) -> {
                if (callback instanceof NameCallback) {
                    NameCallback nc = (NameCallback) callback;
                    nc.setName(principal);
                } else if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    pc.setPassword(password.toCharArray());
                } else {
                    stderr.println("Unknown callback: " + callback.getClass().toString());
                }
            });
        }
    }

    private HashMap<String, ContextToken> getSpns(String hostname, String domain) {
        HashMap<String, ContextToken> results = new HashMap<>();
        //results.put(new StringBuilder("HTTPS/").append(hostname).append("@").append(domain).toString(), null);
        results.put(new StringBuilder("HTTP/").append(hostname).append("@").append(domain).toString(), null);
        return results;
    }

    private class ContextToken {

        private final GSSContext context;
        private final String token;

        public ContextToken(GSSContext context, String token) {
            this.context = context;
            this.token = token;
        }

        public GSSContext getContext() {
            return context;
        }

        public String getToken() {
            return token;
        }
    }

    private class GetTokenPrivilegedAction implements PrivilegedExceptionAction {

        private final HashMap<String, ContextToken> spns;

        public GetTokenPrivilegedAction(HashMap<String, ContextToken> spns) {
            this.spns = spns;
        }

        @Override
        public Object run() throws Exception {
            spns.keySet().forEach((String spn) -> {
                try {
                    String encodedToken;
                    GSSContext context;
                    //Oid krb5MechOid = new Oid("1.2.840.113554.1.2.2");
                    Oid spnegoMechOid = new Oid("1.3.6.1.5.5.2");
                    GSSName gssServerName = manager.createName(spn, null);
                    GSSCredential userCreds = manager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME, spnegoMechOid, GSSCredential.INITIATE_ONLY);
                    context = manager.createContext(gssServerName, spnegoMechOid, userCreds, GSSCredential.INDEFINITE_LIFETIME);
                    ExtendedGSSContext extendedContext = null;
                    if (context instanceof ExtendedGSSContext) {
                        extendedContext = (ExtendedGSSContext) context;
                        extendedContext.requestDelegPolicy(true);
                    }
                    byte spnegoToken[] = new byte[0];
                    spnegoToken = context.initSecContext(spnegoToken, 0, spnegoToken.length);
                    encodedToken = Base64.getEncoder().encodeToString(spnegoToken);
                    stdout.println("[+] got token for " + spn);
                    if (extendedContext != null) {
                        stdout.println(String.format("    getDelegPolicyState = %s for %s", extendedContext.getDelegPolicyState(), spn));
                        stdout.println(String.format("    getCredDelegState = %s for %s", extendedContext.getCredDelegState(), spn));
                    }
                    spns.replace(spn, new ContextToken(context, encodedToken));
                } catch (GSSException ex) {
                    //stderr.println("get token for " + spn);
                    ex.printStackTrace(stderr);
                    spns.replace(spn, null);
                }
            });
            return null;
        }
    }

    private void initialize() {

        stdout.println("[+] started");

        //
        // unlimited JCE?
        //
        stdout.println("    Unlimited Strength Java(TM) Cryptography Extension Policy Files " + (isUnlimitedJCE() ? "detected" : "missing!"));

        //
        // config
        //
        properties = new Properties();
        try {
            properties.load(Negotiate.class.getResourceAsStream("/resources/test-creds.properties"));
        } catch (IOException ex) {
            ex.printStackTrace(stderr);
            return;
        }

        String targetUrl = properties.getProperty("targetURL");
        //String targetHost;
        String domain = properties.getProperty("domain");
        //String realm;
        String kdc = properties.getProperty("kdc");
        String username = properties.getProperty("username");
        String password = properties.getProperty("password");
        //String principal;
        boolean debug = true;

        //
        // obtain kdc
        //
        // [ ]    kdcAuto
        //
        // "_kerberos._tcp.[...]"
        // "_ldap._tcp.dc._msdcs.[...]"
        // org.xbill.DNS.Lookup;
        // Record[] recods = new Lookup(query, Type.SRV).run();
        // (SRVRecord) record
        //
        // ping kdc
        //
        // [ ]    pingKDC
        //
        try (Socket client = new Socket()) {
            client.connect(new InetSocketAddress(kdc, 88), 2000);
        } catch (Exception ex) {
            ex.printStackTrace(stderr);
            return;
        }
        stdout.println("[+] connect to kdc successful");
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
        String targetHost = targetURL.getHost().toLowerCase();
        domain = domain.toUpperCase();
        String realm = Arrays.asList(domain.split("\\.", 2)).get(0).toUpperCase();
        kdc = kdc.toLowerCase();
        username = username.toUpperCase();
        String principal = new StringBuilder(username).append("@").append(domain).toString();

        //
        // print config
        //
        stdout.println("[+] config");
        stdout.println("    target url:   " + targetUrl);
        stdout.println("    target host:  " + targetHost);
        stdout.println("    domain:       " + domain);
        stdout.println("    realm:        " + realm);
        stdout.println("    kdc:          " + kdc);
        stdout.println("    username:     " + username);
        stdout.println("    password:     " + "*********");
        stdout.println("    principal:    " + principal);

        //
        // [ ]    setDefaultConfig
        //        
        System.setProperty("java.security.krb5.conf", "");
        System.setProperty("sun.security.krb5.debug", String.valueOf(debug));
        //
        // [ ]    setDomainAndKdc
        //
        System.setProperty("java.security.krb5.realm", domain.toUpperCase());
        System.setProperty("java.security.krb5.kdc", kdc);
        //
        // [ ]    pingKDC
        //

        //
        // krb5Config
        //
        // [ ]    setKrb5Config
        //
        File krb5Config;
        try {
            krb5Config = File.createTempFile("krb5", ".kdc");
        } catch (IOException ex) {
            ex.printStackTrace(stderr);
            return;
        }
        ArrayList<String> lines = new ArrayList<>();
        lines.add("[libdefaults]");
        lines.add("  forwardable=true");
        //lines.add("  default_realm = " + domain);
        //lines.add("");
        //lines.add("[realms]");
        //lines.add("  " + domain + " = {");
        //lines.add("    kdc = " + kdc);
        //lines.add("    admin_server = " + kdc);
        //lines.add("    default_domain = " + domain);
        //lines.add("  }");
        //lines.add("");
        //lines.add("[domain_realm]");
        //lines.add("  ." + domain + " = " + realm);
        //lines.add("  " + domain + " = " + realm);
        lines.add("");
        String joined = lines.stream().reduce((String t, String u) -> {
            return t + System.lineSeparator() + u;
        }).get();
        // save file
        try (FileWriter writer = new FileWriter(krb5Config)) {
            writer.write(joined);
        } catch (IOException ex) {
            ex.printStackTrace(stderr);
            return;
        }
        stdout.println("[+] krb5config created \"" + krb5Config.getAbsolutePath() + "\"");
        // delete temp file on exit
        krb5Config.deleteOnExit();
        // read file
        try (Scanner scanner = new Scanner(krb5Config).useDelimiter("\r\n")) {
            //stdout.println("    " + scanner.useDelimiter("\\Z").next());
            while (scanner.hasNext()) {
                stdout.println("    " + scanner.next());
            }
        } catch (FileNotFoundException ex) {
            ex.printStackTrace(stderr);
            return;
        }

        //
        // set kerberos configuration
        //
        // [ ]    setupKerberosConfig
        //
        //System.setProperty("java.security.krb5.conf", krb5Config.toURI().toString());
        System.setProperty("java.security.krb5.conf", krb5Config.getAbsolutePath());
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
        //
        Configuration config = new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, Object> map = new HashMap<>();
                map.put("doNotPrompt", "false");
                map.put("useTicketCache", "false");
                map.put("refreshKrb5Config", "true");
                return new AppConfigurationEntry[]{new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, map)};
            }

            @Override
            public void refresh() {
                // ignored
            }

        };
        Configuration.setConfiguration(config);
        stdout.println("[+] kerberos configuration set");

        //
        // [ ]    setupLoginContext
        // [ ]    setCredentials
        // [ ]    testCredentials
        //
        LoginContext loginContext;

        //
        // clear login context
        //
        //synchronized (lock) {
        //    loginContext = null;
        //}
        //
        // log in
        //
        synchronized (lock) {
            try {
                loginContext = new LoginContext("KrbLogin", new KerberosCallBackHandler(principal, password));
                loginContext.login();
            } catch (LoginException ex) {
                stderr.println("log in");
                ex.printStackTrace(stderr);
                return;
            }
        }
        stdout.println("[+] login completed");
        Subject subject = loginContext.getSubject();
        //
        // [ ]    checkTgtForwardableFlag
        //
        boolean forwardable;
        forwardable = subject.getPrivateCredentials().stream().anyMatch((Object t) -> {
            if (t instanceof KerberosTicket) {
                KerberosTicket kt = (KerberosTicket) t;
                boolean[] flags = kt.getFlags();
                return flags[1];
            }
            return false;
        });
        stdout.println("[+] forwardable: " + String.valueOf(forwardable));

        //
        // get token
        //
        // [ ]    hostnameToSpn
        // [ ]    getToken
        // [ ]    GetTokenAction
        //
        // spns for hostname
        HashMap<String, ContextToken> spns = getSpns(targetHost, domain);
        // fetch tokens for spns
        stdout.println("[+] attempt to obtain token");
        synchronized (lock) {
            GetTokenPrivilegedAction getTokenPrivilegedAction = new GetTokenPrivilegedAction(spns);
            try {
                Subject.doAs(subject, getTokenPrivilegedAction);
            } catch (PrivilegedActionException ex) {
                ex.printStackTrace(stderr);
                return;
            }
        }
        // store result
        spns.forEach((String key, ContextToken value) -> {
            if (spnContextToken.containsKey(key) == false) {
                spnContextToken.put(key, value);
            }
            if (value != null && domainSpn.containsKey(targetHost) == false) {
                domainSpn.put(targetHost, key);
            }
        });
        // obtain spn and token
        String spn = null;
        ContextToken contextToken = null;
        if (domainSpn.containsKey(targetHost)) {
            spn = domainSpn.get(targetHost);
            if (spnContextToken.containsKey(spn)) {
                contextToken = spnContextToken.get(spn);
            }
        }
        if (spn == null || contextToken == null) {
            stdout.println("[ ] contextToken missing!");
            return;
        }
        String token = contextToken.getToken();
        stdout.println("[+] new token: " + token.substring(0, 20) + "..." + token.substring(token.length() - 20, token.length()) + " (" + String.valueOf(token.length()) + ")");

        //
        // attempt to contact target service
        //
        // base request (no authentication)
        byte[] baseRequest = helpers.buildHttpRequest(targetURL);
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
        byte[] baseResponse = callbacks.makeHttpRequest(host, port, https, baseRequest);
        IResponseInfo baseResponseInfo = helpers.analyzeResponse(baseResponse);
        stdout.println("[+] base response - status code: " + String.valueOf(baseResponseInfo.getStatusCode()));
        // HTTP/1.1 401 Unauthorized
        // www-authenticate: Negotiate
        //
        // Authorization: Negotiate YII[...]
        //
        // fiddler's token length: 4972
        // generated token length: 6320
        //
        // auth request (with authentication)
        IRequestInfo baseRequestInfo = helpers.analyzeRequest(baseRequest);
        List<String> headers = baseRequestInfo.getHeaders();
        headers.add("Authorization: Negotiate " + token);
        byte[] authRequest = helpers.buildHttpMessage(headers, new byte[0]);
        byte[] authResponse = callbacks.makeHttpRequest(host, port, https, authRequest);
        IResponseInfo authResponseInfo = helpers.analyzeResponse(authResponse);
        stdout.println("[+] auth response - status code: " + String.valueOf(authResponseInfo.getStatusCode()));

        //
        // [ ]    ProcessErrorTokenResponse
        // [ ]    processHttpMessage
        //
        stdout.println("[+] done");

        System.out.println("");
        System.out.println("---");
        System.out.println("");
    }

}
