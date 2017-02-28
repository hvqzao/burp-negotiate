package hvqzao.negotiate;

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;

public class Helper {

    public static boolean isUnlimitedJCE() {
        boolean unlimited = false;
        try {
            unlimited = Cipher.getMaxAllowedKeyLength("RC5") >= 256;
        } catch (NoSuchAlgorithmException ex) {
            // do nothing
        }
        return unlimited;
    }
    
}
