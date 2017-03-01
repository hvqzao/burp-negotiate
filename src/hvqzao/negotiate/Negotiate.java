//
// burp-negotiate, March 2017
//
// The following class source code is AGPLv3 licensed.
//
// Authors:
//
//   - Marcin Woloszyn, @hvqzao
//     https://github.com/hvqzao/burp-negotiate
//
//   - Richard Turnbull, Richard [dot] Turnbull [at] nccgroup [dot] trust
//     https://github.com/nccgroup/Berserko/
//     (original code)
//
package hvqzao.negotiate;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
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
import java.util.Map;
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

    /**
     * Instantiate Negotiate object and initialize it with parameters.
     *
     * @param domain - case insensitive, domain FQDN
     * @param username - case insensitive
     * @param password
     * @param forwardable - forwardable flag
     * @param verbose - verbose output to Burp extension stdout
     * @param debug - Java Kerberos-related debug to console
     */
    public Negotiate(String domain, String username, String password, boolean forwardable, boolean verbose, boolean debug) {
        this.scope = new ArrayList<>();
        this.domainSpn = new HashMap<>();
        this.spnServiceTicket = new HashMap<>();
        this.manager = GSSManager.getInstance();
        this.lock = new Object();
        this.domain = domain;
        kdc = null;
        this.username = username;
        this.password = password;
        this.forwardable = forwardable;
        this.verbose = verbose;
        this.debug = debug;
        stdout = BurpExtender.getStdout();
        stderr = BurpExtender.getStderr();
        lineSeparator = System.lineSeparator(); // System.getProperty("line.separator");
    }

    /**
     * Instantiate Negotiate object and initialize it with parameters.
     *
     * @param domain - case insensitive, domain FQDN
     * @param username - case insensitive
     * @param password
     * @param forwardable - forwardable flag
     */
    public Negotiate(String domain, String username, String password, boolean forwardable) {
        this(domain, username, password, forwardable, false, false);
    }

    /**
     * Instantiate Negotiate object and initialize it with parameters.
     *
     * @param domain - case insensitive, domain FQDN
     * @param username - case insensitive
     * @param password
     */
    public Negotiate(String domain, String username, String password) {
        this(domain, username, password, true, false, false);
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

    private void log(String... text) {
        if (verbose) {
            stdout.print(String.join(" ", text).concat(lineSeparator));
        }
    }

    private void error(String... text) {
        stderr.print(String.join(" ", text).concat(lineSeparator));
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

    public boolean login() {
        //
        // obtain list of kdc's
        //
        // "_kerberos._tcp.[...]"
        // "_ldap._tcp.dc._msdcs.[...]"
        // "_kerberos._tcp.dc._msdcs.[...]"
        ArrayList<String> kdcs = DNS.query(DNS.TYPE_SRV, new StringBuilder("_kerberos._tcp.dc._msdcs.").append(domain.toLowerCase()).toString());
        log(String.format("[+] kdc found (%s)", String.valueOf(kdcs.size())));
        //kdcs.forEach((String k) -> {
        //    log("    " + k);
        //});

        //
        // find reachable kdc
        //
        for (int i = 0; i < kdcs.size(); i++) {
            String k = kdcs.get(i);
            try (Socket client = new Socket()) {
                client.connect(new InetSocketAddress(k, 88), 2000);
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
        this.domain = domain.toUpperCase();
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
        log(String.format("    forwardable:  %s", String.valueOf(forwardable)));

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
            //lines.scopeAdd(String.format("  default_realm = %s", domain));
            //lines.scopeAdd(String.format(""));
            //lines.scopeAdd(String.format("[realms]"));
            //lines.scopeAdd(String.format("  %s = {", domain));
            //lines.scopeAdd(String.format("    kdc = %s", kdc));
            //lines.scopeAdd(String.format("    admin_server = %s", kdc));
            //lines.scopeAdd(String.format("    default_domain = %s", domain));
            //lines.scopeAdd(String.format("  }"));
            //lines.scopeAdd(String.format(""));
            //lines.scopeAdd(String.format("[domain_realm]"));
            //lines.scopeAdd(String.format("  .%s = %s", domain, realm));
            //lines.scopeAdd(String.format("  %s = %s", domain, realm));
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
        System.setProperty("java.security.krb5.realm", domain.toUpperCase());
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
                error("log in");
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
        log(String.format("[+] forwardable: %s", String.valueOf(forwardableStatus)));

        return true;
    }

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
        private final String ticket;

        public ServiceTicket(GSSContext context, String ticket) {
            this.context = context;
            this.ticket = ticket;
        }

        public GSSContext getContext() {
            return context;
        }

        public String getTicket() {
            return ticket;
        }
    }

    public String getTicket(URL targetURL) {
        String targetHost = targetURL.getHost().toLowerCase();

        //
        // print config
        //
        log("[+] ticket config");
        log(String.format("    target url:   %s", targetURL.toString()));
        log(String.format("    target host:  %s", targetHost));

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
        // store result
        spns.forEach((String key, ServiceTicket value) -> {
            if (spnServiceTicket.containsKey(key) == false) {
                spnServiceTicket.put(key, value);
            }
            if (value != null && domainSpn.containsKey(targetHost) == false) {
                domainSpn.put(targetHost, key);
            }
        });
        // obtain spn and ticket
        String spn = null;
        ServiceTicket serviceTicket = null;
        if (domainSpn.containsKey(targetHost)) {
            spn = domainSpn.get(targetHost);
            if (spnServiceTicket.containsKey(spn)) {
                serviceTicket = spnServiceTicket.get(spn);
            }
        }
        if (spn == null || serviceTicket == null) {
            log("[ ] serviceTicket missing!");
            return null;
        }
        String ticket = serviceTicket.getTicket();
        log(String.format("[+] new ticket: %s...%s (%s)", ticket.substring(0, 20), ticket.substring(ticket.length() - 20, ticket.length()), String.valueOf(ticket.length())));
        return ticket;
    }

    /**
     * Add URL to Burp
     * {@link #processHttpMessage(int, boolean, burp.IHttpRequestResponse) processHttpMessage}
     * scope.
     *
     * @param scopeURL
     */
    public void scopeAdd(URL scopeURL) {
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
    public void scopeRemove(URL scopeURL) {
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
    public void scopeClear() {
        scope.clear();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        final URL url = requestInfo.getUrl();
        // is current url in Negotiate scope?
        if (scope.stream().anyMatch((URL scopeURL) -> {
            if (url.getProtocol().equals(scopeURL.getProtocol()) == false) {
                return false;
            }
            if (url.getHost().equals(scopeURL.getHost()) == false) {
                return false;
            }
            if ((url.getPort() == scopeURL.getPort()) == false) {
                return false;
            }
            return url.getPath().startsWith(scopeURL.getPath());
        })) {
            
        }
    }
}
