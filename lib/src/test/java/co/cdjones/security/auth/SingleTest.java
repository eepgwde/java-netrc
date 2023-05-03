package co.cdjones.security.auth;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.InvalidPropertiesFormatException;

import static org.junit.jupiter.api.Assertions.assertNotNull;


public class SingleTest {
    private static final Logger logger = LoggerFactory.getLogger(SingleTest.class);

    @BeforeAll
    public static void setup() {
        logger.info("SingleTest: BeforeAll");
    }

    @Test
    public void t01Test() throws InvalidPropertiesFormatException {
        NetrcParser netrc = NetrcParser.getInstance();
        assertNotNull(netrc);
        Credentials c0 = netrc.getCredentials("localhost");
        assertNotNull(c0);
        logger.info(String.format("t01Test: %s", c0));
    }

    @Test
    public void t03Test() throws InvalidPropertiesFormatException {
        NetrcParser netrc = NetrcParser.getInstance();
        assertNotNull(netrc);
        Credentials c0 = netrc.getCredentials("elvis.69.mu");
        assertNotNull(c0);
        logger.info(String.format("t01Test: %s", c0));
    }

}
