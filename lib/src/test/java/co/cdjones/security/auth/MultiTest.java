package co.cdjones.security.auth;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.InvalidPropertiesFormatException;
import java.util.Stack;

import static org.junit.jupiter.api.Assertions.assertNotNull;


public class MultiTest {
    private static final Logger logger = LoggerFactory.getLogger(MultiTest.class);

    @BeforeAll
    public static void setup() {
        logger.info("SingleTest: BeforeAll");
    }

    @Test
    public void t01Test() throws InvalidPropertiesFormatException {
        NetrcParser netrc = NetrcParser.getInstance();
        assertNotNull(netrc);
        Stack<Credentials> c0 = netrc.getCredentials1("localhost");
        assertNotNull(c0);
        logger.info(String.format("t01Test: %d", c0.size()));

        logger.info(String.format("t01Test: %s", c0.pop().toString()));
    }

    @Test
    public void t03Test() throws InvalidPropertiesFormatException {
        NetrcParser netrc = NetrcParser.getInstance();
        assertNotNull(netrc);
        Stack<Credentials> c0 = netrc.getCredentials1("elvis.69.mu");
        assertNotNull(c0);
        logger.info(String.format("t03est: %d", c0.size()));

        for(Credentials c1 : c0)
            logger.info(String.format("t03Test: %s", c1));
    }

    @Test
    public void t05Test() throws InvalidPropertiesFormatException {
        NetrcParser netrc = NetrcParser.getInstance();
        assertNotNull(netrc);
        Credentials c0 = netrc.getCredentials1("elvis.69.mu", "thebox@elvis.69.mu");
        assertNotNull(c0);
        logger.info(String.format("t05Test: %s", c0));
    }
}
