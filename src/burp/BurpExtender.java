package burp;

import com.codemagi.burp.BaseExtender;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

/**
 * Burp Extender to warn if the Java Unlimited Cryptography Extension (UCE) is not installed
 * 
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class BurpExtender extends BaseExtender {

    @Override
    protected void initialize() {
        try {
            boolean unlimited = Cipher.getMaxAllowedKeyLength("RC5") >= 256;
            callbacks.printOutput("Unlimited cryptography enabled? " + unlimited);
            
            if (!unlimited) callbacks.issueAlert("Warning: Java Unlimited Cryptography exension not installed.");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
