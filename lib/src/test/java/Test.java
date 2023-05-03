import co.cdjones.security.auth.NetrcParser;
import co.cdjones.security.auth.Credentials;

import java.util.InvalidPropertiesFormatException;

public class Test {
    public static void main(String[] args) throws InvalidPropertiesFormatException {
        NetrcParser netrc = NetrcParser.getInstance();
        Credentials credentials = netrc.getCredentials("localhost");

        System.out.println(credentials.user());
    }
}
