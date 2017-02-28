package hvqzao.negotiate;

import java.util.ArrayList;
import java.util.Hashtable;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

public class DNS {

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
            ex.printStackTrace(NegotiateExtension.getStderr());
        }
        return entries;
    }

}
