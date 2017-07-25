//
// burp-negotiate, March 2017
//
// The following class source code is AGPLv3 licensed.
//
// Author:
//
//   - Marcin Woloszyn, @hvqzao
//     https://github.com/hvqzao/burp-negotiate
//
// Acknowledgement:
//
//   - Richard Turnbull, Richard [dot] Turnbull [at] nccgroup [dot] trust
//     https://github.com/nccgroup/Berserko/
//     (original code)
//
package hvqzao.negotiate;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.sun.security.jgss.ExtendedGSSContext;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
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
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class Negotiate implements IHttpListener {

    private final int TCP_CONNECT_TIMEOUT = 4000;
    private String domain;
    private String kdc;
    private String username;
    private final String password;
    private final boolean forwardable;
    private boolean verbose;
    private boolean debug;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    private final Object lock;
    private final GSSManager manager;
    private LoginContext loginContext;
    private final HashMap<String, ServiceTicket> spnServiceTicket;
    private final HashMap<String, String> domainSpn;
    private final String lineSeparator;
    private final ArrayList<URL> scope;
    private boolean enabled;
    private boolean registered;
    private boolean proactive;
    private boolean cacheEnabled;

    /**
     * Instantiate Negotiate object and initialize it with parameters.
     *
     * @param domain - case insensitive, domain FQDN
     * @param username - case insensitive
     * @param password
     * @param proactive - proactive / reactive mode
     * @param cacheEnabled - tickets cache
     * @param forwardable - forwardable flag
     * @param verbose - verbose output to Burp extension stdout
     * @param debug - Java Kerberos-related debug to console
     */
    public Negotiate(String domain, String username, String password, boolean proactive, boolean cacheEnabled, boolean forwardable, boolean verbose, boolean debug) {
        scope = new ArrayList<>();
        domainSpn = new HashMap<>();
        spnServiceTicket = new HashMap<>();
        manager = GSSManager.getInstance();
        lock = new Object();
        this.domain = domain;
        kdc = null;
        this.username = username;
        this.password = password;
        this.proactive = proactive;
        this.cacheEnabled = cacheEnabled;
        this.forwardable = forwardable;
        this.verbose = verbose;
        this.debug = debug;
        stdout = BurpExtender.getStdout();
        stderr = BurpExtender.getStderr();
        lineSeparator = System.lineSeparator(); // System.getProperty("line.separator");
        enabled = true;
        registered = false;
    }

    /**
     * Instantiate Negotiate object and initialize it with parameters.
     *
     * @param domain - case insensitive, domain FQDN
     * @param username - case insensitive
     * @param password
     * @param proactive - proactive / reactive mode
     * @param cacheEnabled - tickets cache
     * @param forwardable - forwardable flag
     */
    public Negotiate(String domain, String username, String password, boolean proactive, boolean cacheEnabled, boolean forwardable) {
        this(domain, username, password, proactive, cacheEnabled, forwardable, false, false);
    }

    /**
     * Instantiate Negotiate object and initialize it with parameters.
     *
     * @param domain - case insensitive, domain FQDN
     * @param username - case insensitive
     * @param password
     * @param proactive - proactive / reactive mode
     * @param cacheEnabled - tickets cache
     */
    public Negotiate(String domain, String username, String password, boolean proactive, boolean cacheEnabled) {
        this(domain, username, password, proactive, cacheEnabled, true, false, false);
    }

    /**
     * Instantiate Negotiate object and initialize it with parameters.
     *
     * @param domain - case insensitive, domain FQDN
     * @param username - case insensitive
     * @param password
     */
    public Negotiate(String domain, String username, String password) {
        this(domain, username, password, false, true, true, false, false);
    }

    /**
     * Unlimited Strength Java(TM) Cryptography Extension Policy Files check.
     *
     * "Due to export control restrictions, JDK 5.0 environments do not ship
     * with support for AES-256 enabled. Kerberos uses AES-256 in the
     * 'aes256-cts-hmac-sha1-96' encryption type. To enable AES-256, you must
     * download "unlimited strength" policy JAR files for your JRE. Policy JAR
     * files are signed by the JRE vendor so you must download policy JAR files
     * for Sun, IBM, etc. separately. Also, policy files may be different for
     * each platform, such as i386, Solaris, or HP."
     *
     * Source:
     * https://cwiki.apache.org/confluence/display/DIRxSRVx10/Kerberos+and+Unlimited+Strength+Policy
     *
     * @return status
     */
    public static boolean isUnlimitedJCE() {
        boolean unlimited = false;
        try {
            unlimited = Cipher.getMaxAllowedKeyLength("RC5") >= 256;
        } catch (NoSuchAlgorithmException ex) {
            // do nothing
        }
        return unlimited;
    }

    private void log(String... text) {
        if (verbose) {
            stdout.println(String.join(" ", text));
        }
    }

    private void error(String... text) {
        stderr.println(String.join(" ", text));
    }

    private abstract static class DNS {

        public static final String TYPE_SRV = "SRV";

        public static ArrayList<String> query(String type, String domain) {
            final ArrayList<String> entries = new ArrayList<>();
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext dnsContext;
            try {
                dnsContext = new InitialDirContext(env);
                Attributes attributes = dnsContext.getAttributes(domain, new String[]{type});
                if (attributes != null) {
                    Attribute attribute = attributes.get(type);
                    if (attribute != null) {
                        for (int i = 0; i < attribute.size(); i++) {
                            String s = (String) attribute.get(i);
                            String[] parts = s.split(" ");
                            String namePart = parts[parts.length - 1];
                            if (namePart.endsWith(".")) {
                                namePart = namePart.substring(0,
                                        namePart.length() - 1);
                            }
                            entries.add(namePart);
                        }
                    }
                }
            } catch (NamingException ex) {
                ex.printStackTrace(BurpExtender.getStderr());
            }
            return entries;
        }
    }

    /**
     * Log in.
     *
     * @return success
     */
    public boolean login() {
        //
        // obtain list of kdc's
        //
        // "_kerberos._tcp.[...]"
        // "_ldap._tcp.dc._msdcs.[...]"
        // "_kerberos._tcp.dc._msdcs.[...]"
        ArrayList<String> kdcs = DNS.query(DNS.TYPE_SRV, new StringBuilder("_kerberos._tcp.dc._msdcs.").append(domain.toLowerCase()).toString());
        log(String.format("[+] kdc found (%d)", kdcs.size()));
        //kdcs.forEach((String k) -> {
        //    log(String.format("    %s", k));
        //});

        //
        // find reachable kdc
        //
        for (int i = 0; i < kdcs.size(); i++) {
            String k = kdcs.get(i);
            try (Socket client = new Socket()) {
                client.connect(new InetSocketAddress(k, 88), TCP_CONNECT_TIMEOUT);
                kdc = k;
                break;
            } catch (Exception ex) {
                log(String.format("[ ] connect to %s:%d failed!", k, 88));
                ex.printStackTrace(stderr);
                return false;
            }
        }
        if (kdc == null) {
            log("[ ] no reachable kdc found!");
            return false;
        }
        log(String.format("[+] connect to kdc (%s) successful", kdc));

        //
        // mangle config
        //
        domain = domain.toUpperCase();
        String realm = Arrays.asList(domain.split("\\.", 2)).get(0).toUpperCase();
        kdc = kdc.toLowerCase();
        username = username.toUpperCase();
        String principal = new StringBuilder(username).append("@").append(domain).toString();

        //
        // print config
        //
        log("[+] login config");
        log(String.format("    domain:       %s", domain));
        log(String.format("    realm:        %s", realm));
        log(String.format("    kdc:          %s", kdc));
        log(String.format("    username:     %s", username));
        log(String.format("    password:     %s", "*********"));
        log(String.format("    principal:    %s", principal));
        log(String.format("    forwardable:  %b", forwardable));
        log(String.format("    cache:        %s", cacheEnabled ? "enabled" : "disabled"));

        //
        // build krb5 config
        //
        if (forwardable) {
            File krb5Config;
            try {
                krb5Config = File.createTempFile("krb5", ".kdc");
            } catch (IOException ex) {
                ex.printStackTrace(stderr);
                return false;
            }
            ArrayList<String> lines = new ArrayList<>();
            lines.add(String.format("[libdefaults]"));
            lines.add(String.format("  forwardable=true"));
            //lines.add(String.format("  default_realm = %s", domain));
            //lines.add(String.format(""));
            //lines.add(String.format("[realms]"));
            //lines.add(String.format("  %s = {", domain));
            //lines.add(String.format("    kdc = %s", kdc));
            //lines.add(String.format("    admin_server = %s", kdc));
            //lines.add(String.format("    default_domain = %s", domain));
            //lines.add(String.format("  }"));
            //lines.add(String.format(""));
            //lines.add(String.format("[domain_realm]"));
            //lines.add(String.format("  .%s = %s", domain, realm));
            //lines.add(String.format("  %s = %s", domain, realm));
            lines.add("");
            String joined = lines.stream().reduce((String t, String u) -> {
                return String.join("", t, lineSeparator, u);
            }).get();
            // save file
            try (FileWriter writer = new FileWriter(krb5Config)) {
                writer.write(joined);
            } catch (IOException ex) {
                ex.printStackTrace(stderr);
                return false;
            }
            log(String.format("[+] krb5config created \"%s\"", krb5Config.getAbsolutePath()));
            // delete temp file on exit
            krb5Config.deleteOnExit();
            // read file
            try (Scanner scanner = new Scanner(krb5Config).useDelimiter(lineSeparator)) {
                //log(String.format("    %s", scanner.useDelimiter("\\Z").next()));
                while (scanner.hasNext()) {
                    log(String.format("    %s", scanner.next()));
                }
            } catch (FileNotFoundException ex) {
                ex.printStackTrace(stderr);
                return false;
            }
            //System.setProperty("java.security.krb5.conf", krb5Config.toURI().toString());
            System.setProperty("java.security.krb5.conf", krb5Config.getAbsolutePath());
        } else {
            System.setProperty("java.security.krb5.conf", "");
        }

        //
        // set kerberos configuration
        //
        System.setProperty("sun.security.krb5.debug", String.valueOf(debug));
        System.setProperty("java.security.krb5.realm", domain);
        System.setProperty("java.security.krb5.kdc", kdc);
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
        //
        Configuration config = new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, Object> map = new HashMap<>();
                map.put("doNotPrompt", "false"); // false, useFirstPass, ...?
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
        log("[+] kerberos configuration set");

        //
        // log in
        //
        synchronized (lock) {
            try {
                loginContext = new LoginContext("KrbLogin", new KerberosCallBackHandler(principal, password));
                loginContext.login();
            } catch (LoginException ex) {
                ex.printStackTrace(stderr);
                return false;
            }
        }
        log("[+] login completed");
        Subject subject = loginContext.getSubject();

        //
        // check forwardable flag status
        //
        boolean forwardableStatus;
        forwardableStatus = subject.getPrivateCredentials().stream().anyMatch((Object t) -> {
            if (t instanceof KerberosTicket) {
                KerberosTicket kt = (KerberosTicket) t;
                boolean[] flags = kt.getFlags();
                return flags[1];
            }
            return false;
        });
        log(String.format("[+] forwardable: %b", forwardableStatus));

        // clear cache and domain spn mapping
        clearMapping();
        clearCache();

        return true;
    }

    /**
     * Log out.
     *
     */
    public void logout() {
        // 
        // logout and clear login context
        //
        synchronized (lock) {
            if (loginContext != null) {
                try {
                    loginContext.logout();
                } catch (LoginException ex) {
                    ex.printStackTrace(stderr);
                }
                loginContext = null;
            }
        }

        // clear cache and domain spn mapping
        clearMapping();
        clearCache();
    }

    /**
     * Is logged in?
     *
     * @return status
     */
    public boolean isLoggedIn() {
        return loginContext != null;
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
                    error(String.format("Unknown callback: %s", callback.getClass().toString()));
                }
            });
        }
    }

    private HashMap<String, ServiceTicket> getSpns(String hostname, String domain) {
        HashMap<String, ServiceTicket> results = new HashMap<>();
        //results.put(new StringBuilder("HTTPS/").append(hostname).append("@").append(domain).toString(), null);
        results.put(new StringBuilder("HTTP/").append(hostname).append("@").append(domain).toString(), null);
        return results;
    }

    private class GetTicketPrivilegedAction implements PrivilegedExceptionAction {

        public static final String KRB_5 = "1.2.840.113554.1.2.2";
        public static final String SPNEGO = "1.3.6.1.5.5.2";
        private final String oid;
        private final HashMap<String, ServiceTicket> spns;

        public GetTicketPrivilegedAction(String oid, HashMap<String, ServiceTicket> spns) {
            this.oid = oid;
            this.spns = spns;
        }

        @Override
        public Object run() throws Exception {
            spns.keySet().forEach((String spn) -> {
                try {
                    String encodedServiceTicket;
                    GSSContext context;
                    Oid mechOid = new Oid(oid);
                    GSSName gssServerName = manager.createName(spn, null);
                    GSSCredential userCreds = manager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME, mechOid, GSSCredential.INITIATE_ONLY);
                    context = manager.createContext(gssServerName, mechOid, userCreds, GSSCredential.INDEFINITE_LIFETIME);
                    ExtendedGSSContext extendedContext = null;
                    if (forwardable && context instanceof ExtendedGSSContext) {
                        extendedContext = (ExtendedGSSContext) context;
                        extendedContext.requestDelegPolicy(true);
                    }
                    byte serviceTicket[] = new byte[0];
                    serviceTicket = context.initSecContext(serviceTicket, 0, serviceTicket.length);
                    encodedServiceTicket = Base64.getEncoder().encodeToString(serviceTicket);
                    log(String.format("[+] ticket for %s obtained", spn));
                    if (forwardable && extendedContext != null) {
                        log(String.format("    getDelegPolicyState = %s for %s", extendedContext.getDelegPolicyState(), spn));
                        log(String.format("    getCredDelegState = %s for %s", extendedContext.getCredDelegState(), spn));
                    }
                    spns.replace(spn, new ServiceTicket(context, encodedServiceTicket));
                } catch (GSSException ex) {
                    error(String.format("[+] failed to obtain ticket for %s", spn));
                    //ex.printStackTrace(stderr);
                    spns.replace(spn, null);
                }
            });
            return null;
        }
    }

    private class ServiceTicket {

        private final GSSContext context;
        private final String cachedToken;

        public ServiceTicket(GSSContext context, String token) {
            this.context = context;
            this.cachedToken = token;
        }

        public GSSContext getContext() {
            return context;
        }

        public String getCachedToken() {
            return cachedToken;
        }
    }

    private String getHost(URL url) {
        return url.getHost().toLowerCase();
    }

    private ServiceTicket getServiceTicket(String targetHost) {
        ServiceTicket serviceTicket = null;
        if (domainSpn.containsKey(targetHost)) {
            String spn = domainSpn.get(targetHost);
            if (spnServiceTicket.containsKey(spn)) {
                serviceTicket = spnServiceTicket.get(spn);
            }
        }
        return serviceTicket;
    }

    /**
     * Get token.
     *
     * @param targetURL
     * @param cached
     * @return
     */
    public String getToken(URL targetURL, boolean cached) {
        String targetHost = getHost(targetURL);

        //
        // print config
        //
        log("[+] ticket config");
        log(String.format("    target url:   %s", targetURL.toString()));
        log(String.format("    target host:  %s", targetHost));

        ServiceTicket serviceTicket;

        //
        // get cached token
        //
        if (cached) {
            serviceTicket = getServiceTicket(targetHost);
            if (serviceTicket != null) {
                log("[+] cache hit");
                return serviceTicket.getCachedToken();
            }
            log("[+] cache miss");
        }

        //
        // spns for hostname
        //
        HashMap<String, ServiceTicket> spns = getSpns(targetHost, domain);

        //
        // fetch tickets for spns
        //
        log("[+] attempt to obtain ticket");
        synchronized (lock) {
            Subject subject = loginContext.getSubject();
            GetTicketPrivilegedAction getTicketPrivilegedAction = new GetTicketPrivilegedAction(GetTicketPrivilegedAction.SPNEGO, spns);
            try {
                Subject.doAs(subject, getTicketPrivilegedAction);
            } catch (PrivilegedActionException ex) {
                ex.printStackTrace(stderr);
                return null;
            }
        }
        // store result in cache
        spns.forEach((String key, ServiceTicket value) -> {
            if (spnServiceTicket.containsKey(key) == false) {
                spnServiceTicket.put(key, value);
            }
            if (value != null && domainSpn.containsKey(targetHost) == false) {
                domainSpn.put(targetHost, key);
            }
        });
        // obtain service ticket and its token from cache
        serviceTicket = getServiceTicket(targetHost);
        if (serviceTicket == null) {
            log("[ ] serviceTicket missing!");
            return null;
        }
        String token = serviceTicket.getCachedToken();
        log(String.format("[+] new token: %s[...] (%d)", token.substring(0, 10), token.length()));
        return token;
    }

    /**
     * Get token (preferably cached).
     *
     * @param targetURL
     * @return
     */
    public String getToken(URL targetURL) {
        return getToken(targetURL, true);
    }

    /**
     * Clear domain-SPN mapping.
     *
     */
    public void clearMapping() {
        domainSpn.clear();
    }

    /**
     * Clear Service Ticket cache.
     *
     */
    public void clearCache() {
        spnServiceTicket.clear();
    }

    /**
     * Add URL to Burp
     * {@link #processHttpMessage(int, boolean, burp.IHttpRequestResponse) processHttpMessage}
     * scope.
     *
     * @param scopeURL
     */
    public void add(URL scopeURL) {
        if (scope.contains(scopeURL) == false) {
            scope.add(scopeURL);
        }
    }

    /**
     * Remove URL from Burp
     * {@link #processHttpMessage(int, boolean, burp.IHttpRequestResponse) processHttpMessage}
     * scope.
     *
     * @param scopeURL
     */
    public void remove(URL scopeURL) {
        if (scope.contains(scopeURL)) {
            scope.remove(scopeURL);
        }
    }

    /**
     * Clear Burp
     * {@link #processHttpMessage(int, boolean, burp.IHttpRequestResponse) processHttpMessage}
     * scope.
     *
     */
    public void clear() {
        scope.clear();
    }

    private boolean isUnauthenticated(IResponseInfo responseInfo) {
        return responseInfo.getStatusCode() == 401 && responseInfo.getHeaders().stream().anyMatch((String header) -> {
            return "www-authenticate: negotiate".equals(header.trim().toLowerCase());
        });
    }

    private boolean isHttps(URL url) {
        return url.toString().trim().toLowerCase().startsWith("https://");
    }

    private int getPort(URL url) {
        int port = url.getPort();
        if (port == -1) {
            if (isHttps(url) == false) {
                port = 80;
            } else {
                port = 443;
            }
        }
        return port;
    }

    /**
     * Is processing http messages enabled?
     *
     * @return status
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enable or disable processing http messages.
     *
     * @param enabled status
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isProactive() {
        return proactive;
    }

    public void setProactive(boolean proactive) {
        this.proactive = proactive;
    }

    /**
     * Get an exception from error token response.
     *
     * @param context
     * @param returnedToken
     */
    private void processErrorTokenResponse(GSSContext context, String returnedToken) {
        byte[] tokenBytes;
        try {
            tokenBytes = Base64.getDecoder().decode(returnedToken);
        } catch (Exception ex) {
            error("Failed to base64-decode Negotiate token from server");
            return;
        }
        try {
            context.initSecContext(tokenBytes, 0, tokenBytes.length);
        } catch (GSSException ex) {
            // this is an "expected" exception - we're deliberately feeding in
            // an error token from the server to collect the corresponding
            // exception
            ex.printStackTrace(stderr);
        }
    }

    /**
     * Register auto-Negotiate HttpListener.
     *
     */
    public void register() {
        if (registered == false) {
            IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
            callbacks.registerHttpListener(this);
            registered = true;
        }
    }

    /**
     * Unregister auto-Negotiate HttpListener.
     *
     */
    public void unregister() {
        if (registered) {
            IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
            callbacks.removeHttpListener(this);
            registered = false;
        }
    }

    /**
     * Is auto-Negotiate already registered as HttpListener?
     *
     * @return
     */
    public boolean isRegistered() {
        return registered;
    }

    //
    // IHttpListener implementation
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (enabled && scope.size() > 0 && loginContext != null && messageIsRequest == false) {
            try {
                final String NEGOTIATE_HEADER = "Authorization: Negotiate ";
                final String NEGOTIATE_HEADER_LOWERCASE = NEGOTIATE_HEADER.toLowerCase();
                IExtensionHelpers helpers = BurpExtender.getHelpers();
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                final URL url = requestInfo.getUrl();
                // is current url in Negotiate scope?
                boolean isInScope = scope.stream().anyMatch((URL scopeURL) -> {
                    if (url.getProtocol().equals(scopeURL.getProtocol()) == false) {
                        return false;
                    }
                    if (url.getHost().equals(scopeURL.getHost()) == false) {
                        return false;
                    }
                    if (getPort(url) != getPort(scopeURL)) {
                        return false;
                    }
                    return url.getPath().startsWith(scopeURL.getPath());
                });
                if (isInScope == false) {
                    log("[+] Ignoring (out of scope) URL:", url.toString());
                } else {
                    IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
                    List<String> headers = requestInfo.getHeaders();
                    boolean authenticate = false;
                    if (isProactive() == false) {
                        // reactive mode: add negotiate header to request only if unauthenticated
                        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
                        if (isUnauthenticated(responseInfo)) {
                            authenticate = true;
                        }
                    } else {
                        // proactive mode: add negotiate header to every request
                        authenticate = true;
                    }
                    // avoid recursion - already attempting to authenticate?
                    if (authenticate && headers.stream().anyMatch((String header) -> {
                        return header.toLowerCase().startsWith(NEGOTIATE_HEADER_LOWERCASE);
                    }) == false) {
                        List<Boolean> cacheAttempts;
                        if (cacheEnabled == false) {
                            cacheAttempts = Arrays.asList(false);
                        } else {
                            // attempt to use cached token first, otherwise try to get new one
                            cacheAttempts = Arrays.asList(true, false);
                        }
                        log("cache enabled: ", String.valueOf(cacheEnabled));
                        for (boolean cached : cacheAttempts) {
                            log();
                            if (debug) {
                                System.out.println();
                            }
                            log(String.format("[+] getting authentication token, cached: %b", cached));
                            String token = getToken(url, cached);
                            if (token != null) {
                                headers.add(new StringBuilder(NEGOTIATE_HEADER).append(token).toString());
                                byte[] authRequest = helpers.buildHttpMessage(headers, new byte[0]);
                                IHttpRequestResponse authMessageInfo = callbacks.makeHttpRequest(messageInfo.getHttpService(), authRequest);
                                byte[] authResponse = authMessageInfo.getResponse();
                                if (authResponse == null) {
                                    log("[ ] request failed.");
                                    break;
                                }
                                IResponseInfo authResponseInfo = helpers.analyzeResponse(authResponse);
                                messageInfo.setResponse(authResponse);
                                if (isUnauthenticated(authResponseInfo) == false) {
                                    log(String.format("[ ] got 401, cached: %b", cached));
                                    break;
                                } else {
                                    log(String.format("[+] got %d, cached: %b", authResponseInfo.getStatusCode(), cached));
                                }
                                // check if we received an error token response
                                Optional<String> optionalHeader = authResponseInfo.getHeaders().stream().map((String header) -> {
                                    return header.trim().replaceAll("\\s+", " ");
                                }).filter((String header) -> {
                                    return header.toLowerCase().startsWith("www-authenticate: negotiate ");
                                }).findFirst();
                                if (optionalHeader.isPresent()) {
                                    log("[+] got error token response!");
                                    String responseToken = Arrays.asList(optionalHeader.get().split("\\s", 3)).get(2);
                                    GSSContext context = getServiceTicket(getHost(url)).getContext();
                                    processErrorTokenResponse(context, responseToken);
                                }
                            }
                        }
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace(stderr);
            }
        }
    }
}
