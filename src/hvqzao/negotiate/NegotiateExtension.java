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

public class NegotiateExtension implements IBurpExtender {

    private Properties properties;
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private final GSSManager manager = GSSManager.getInstance();
    private final Object lock = new Object();
    private final HashMap<String, ServiceTicket> spnServiceTicket = new HashMap<>();
    private final HashMap<String, String> domainSpn = new HashMap<>();

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
        initialize();
    }

    public static PrintWriter getStderr() {
        return stderr;
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

    private HashMap<String, ServiceTicket> getSpns(String hostname, String domain) {
        HashMap<String, ServiceTicket> results = new HashMap<>();
        //results.put(new StringBuilder("HTTPS/").append(hostname).append("@").append(domain).toString(), null);
        results.put(new StringBuilder("HTTP/").append(hostname).append("@").append(domain).toString(), null);
        return results;
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
                    if (context instanceof ExtendedGSSContext) {
                        extendedContext = (ExtendedGSSContext) context;
                        extendedContext.requestDelegPolicy(true);
                    }
                    byte serviceTicket[] = new byte[0];
                    serviceTicket = context.initSecContext(serviceTicket, 0, serviceTicket.length);
                    encodedServiceTicket = Base64.getEncoder().encodeToString(serviceTicket);
                    stdout.println("[+] ticket for " + spn + " obtained");
                    if (extendedContext != null) {
                        stdout.println(String.format("    getDelegPolicyState = %s for %s", extendedContext.getDelegPolicyState(), spn));
                        stdout.println(String.format("    getCredDelegState = %s for %s", extendedContext.getCredDelegState(), spn));
                    }
                    spns.replace(spn, new ServiceTicket(context, encodedServiceTicket));
                } catch (GSSException ex) {
                    stderr.println("[+] failed to get ticket for " + spn);
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
        stdout.println("    Unlimited Strength Java(TM) Cryptography Extension Policy Files " + (Helper.isUnlimitedJCE() ? "detected" : "missing!"));

        //
        // config
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
        String kdc = null;
        String username = properties.getProperty("username");
        String password = properties.getProperty("password");
        //String principal;
        boolean debug = Arrays.asList("1", "true", "yes").contains(properties.getProperty("debug").trim().toLowerCase());

        //
        // obtain kdc
        //
        // [ ]    kdcAuto
        //
        // "_kerberos._tcp.[...]"
        // "_ldap._tcp.dc._msdcs.[...]"
        // "_kerberos._tcp.dc._msdcs.[...]"
        ArrayList<String> kdcs = DNS.query(DNS.TYPE_SRV, new StringBuilder("_kerberos._tcp.dc._msdcs.").append(domain.toLowerCase()).toString());
        stdout.println("[+] kdc found (" + String.valueOf(kdcs.size()) + ")");
        //kdcs.forEach((String k) -> {
        //    stdout.println("    " + k);
        //});

        // ping kdc
        //
        // [ ]    pingKDC
        //
        for (int i = 0; i < kdcs.size() ; i++) {
            String k = kdcs.get(i);
            try (Socket client = new Socket()) {
                client.connect(new InetSocketAddress(k, 88), 2000);
                kdc = k;
                break;
            } catch (Exception ex) {
                stdout.println("[ ] connect to " + k + ":88 failed!");
                ex.printStackTrace(stderr);
                return;
            }
        }
        if (kdc == null) {
            stdout.println("[ ] no reachable kdc found!");
            return;
        }
        stdout.println("[+] connect to kdc (" + kdc + ") successful");
        
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
        // krb5Config
        //
        // [ ]    setKrb5Config
        // [ ]    setDefaultConfig
        // [ ]    setDomainAndKdc
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
        try (Scanner scanner = new Scanner(krb5Config).useDelimiter(System.getProperty("line.separator"))) {
            //stdout.println("    " + scanner.useDelimiter("\\Z").next());
            while (scanner.hasNext()) {
                stdout.println("    " + scanner.next());
            }
        } catch (FileNotFoundException ex) {
            ex.printStackTrace(stderr);
            return;
        }
        //System.setProperty("java.security.krb5.conf", krb5Config.toURI().toString());
        System.setProperty("java.security.krb5.conf", krb5Config.getAbsolutePath());
        System.setProperty("java.security.krb5.conf", "");
        System.setProperty("sun.security.krb5.debug", String.valueOf(debug));
        System.setProperty("java.security.krb5.realm", domain.toUpperCase());
        System.setProperty("java.security.krb5.kdc", kdc);

        //
        // set kerberos configuration
        //
        // [ ]    setupKerberosConfig
        //
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
        stdout.println("[+] kerberos configuration set");

        LoginContext loginContext;

        //
        // clear login context
        //
        synchronized (lock) {
            loginContext = null;
        }

        //
        // log in
        //
        // [ ]    setupLoginContext
        // [ ]    setCredentials
        // [ ]    testCredentials
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
        stdout.println("[+] request forwardable ticket: " + String.valueOf(forwardable));

        //
        // get ticket
        //
        // [ ]    hostnameToSpn
        // [ ]    getToken
        // [ ]    GetTokenAction
        //
        // spns for hostname
        HashMap<String, ServiceTicket> spns = getSpns(targetHost, domain);
        // fetch tickets for spns
        stdout.println("[+] attempt to obtain ticket");
        synchronized (lock) {
            GetTicketPrivilegedAction getTicketPrivilegedAction = new GetTicketPrivilegedAction(GetTicketPrivilegedAction.SPNEGO, spns);
            try {
                Subject.doAs(subject, getTicketPrivilegedAction);
            } catch (PrivilegedActionException ex) {
                ex.printStackTrace(stderr);
                return;
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
            stdout.println("[ ] serviceTicket missing!");
            return;
        }
        String ticket = serviceTicket.getTicket();
        stdout.println("[+] new ticket: " + ticket.substring(0, 20) + "..." + ticket.substring(ticket.length() - 20, ticket.length()) + " (" + String.valueOf(ticket.length()) + ")");

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
        // www-authenticate: NegotiateExtension
        //
        // Authorization: NegotiateExtension YII[...]
        //
        // fiddler's ticket length: 4972
        // generated ticket length: 6320 (SPNEGO), 6256 (KRB_5)
        //
        // auth request (with authentication)
        IRequestInfo baseRequestInfo = helpers.analyzeRequest(baseRequest);
        List<String> headers = baseRequestInfo.getHeaders();
        headers.add("Authorization: Negotiate " + ticket);
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
