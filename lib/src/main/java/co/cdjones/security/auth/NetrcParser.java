package co.cdjones.security.auth;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.InvalidPropertiesFormatException;
import java.util.Map;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Simple match on hostname.
 * <p>
 * Unfortunately, it does not handle multiple logins at the same host.
 * It puts the last identified host, user, password tuple into the hosts.
 *
 * @author chrisjones
 * @date 11/10/2017
 */
public class NetrcParser {
    private static final Pattern NETRC_TOKEN = Pattern.compile("(\\S+)");
    private final File netrc;
    private long lastModified;
    private final Map<String, Credentials> hosts = new HashMap<>();
    private final Map<String, Stack<Credentials>> hosts1 = new HashMap<>();
    // Pattern for detecting comments
    private final Pattern commentPattern = Pattern.compile("(^|\\s)#\\s");

    private NetrcParser(File netrc) {
        this.netrc = netrc;
    }

    /**
     * getInstance.
     *
     * @return a {@link NetrcParser} object.
     */
    public static NetrcParser getInstance() throws InvalidPropertiesFormatException {
        File netrc = getDefaultFile();
        return getInstance(netrc);
    }

    /**
     * getInstance.
     *
     * @param netrcPath a {@link java.lang.String} object.
     * @return a {@link NetrcParser} object.
     */
    public static NetrcParser getInstance(String netrcPath) throws InvalidPropertiesFormatException {
        File netrc = new File(netrcPath);
        return netrc.exists() ? getInstance(new File(netrcPath)) : null;
    }

    /**
     * getInstance.
     *
     * @param netrc a {@link java.io.File} object.
     * @return a {@link NetrcParser} object.
     */
    public static NetrcParser getInstance(File netrc) throws InvalidPropertiesFormatException {
        return new NetrcParser(netrc).parse();
    }

    private static File getDefaultFile() {
        File home = new File(System.getProperty("user.home"));
        File netrc = new File(home, ".netrc");
        if (!netrc.exists()) netrc = new File(home, "_netrc"); // windows variant
        return netrc;
    }

    /**
     * getCredentials.
     *
     * @param host a {@link java.lang.String} object.
     * @return a {@link Credentials} object.
     */
    public synchronized Credentials getCredentials(String host) throws InvalidPropertiesFormatException {
        if (!this.netrc.exists()) return null;
        if (this.lastModified != this.netrc.lastModified()) parse();
        return this.hosts.get(host);
    }

    public synchronized Stack<Credentials> getCredentials1(String host) throws InvalidPropertiesFormatException {
        this.getCredentials(host);
        return this.hosts1.get(host);
    }

    public synchronized Credentials getCredentials1(String host, String user) throws InvalidPropertiesFormatException {
        Stack<Credentials> stk = this.getCredentials1(host);
        if (stk == null || stk.size() == 0)
            throw new InvalidPropertiesFormatException("empty credentials for " + host);

        Credentials result = null;
        for(Credentials c1 : stk) {
            if (c1.user().equals(user)) {
                result = c1;
                break;
            }
        }
        if (result == null)
            throw new InvalidPropertiesFormatException("empty credentials for " + host + " ; " + user);

        return(result);
    }

    synchronized private NetrcParser parse() throws InvalidPropertiesFormatException {
        if (!netrc.exists()) return this;

        this.hosts.clear();
        this.hosts1.clear();
        this.lastModified = this.netrc.lastModified();

        try (BufferedReader r = new BufferedReader(new InputStreamReader(Files.newInputStream(netrc.toPath()), Charset.defaultCharset()))) {
            String line;
            String machine = null;
            String login = null;
            String password = null;

            ParseState state = ParseState.START;
            Matcher commentMatcher = commentPattern.matcher(""); // Matcher to remove comments on each line before parsing
            Matcher matcher = NETRC_TOKEN.matcher("");

            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    if (state == ParseState.MACDEF) {
                        state = ParseState.REQ_KEY;
                    }
                    continue;
                }

                // Remove comments before paring
                commentMatcher.reset(line);
                if (commentMatcher.find()) {
                    // We found a comment, so truncate the string from that point on and clean it up
                    line = line.substring(0, commentMatcher.start()).trim();
                }

                matcher.reset(line);
                while (matcher.find()) {
                    String match = matcher.group();
                    switch (state) {
                        case START:
                            if ("machine".equals(match)) {
                                state = ParseState.MACHINE;
                            }
                            break;

                        case REQ_KEY:
                            if ("login".equals(match)) {
                                state = ParseState.LOGIN;
                            } else if ("password".equals(match)) {
                                state = ParseState.PASSWORD;
                            } else if ("macdef".equals(match)) {
                                state = ParseState.MACDEF;
                            } else if ("machine".equals(match)) {
                                state = ParseState.MACHINE;
                            } else {
                                state = ParseState.REQ_VALUE;
                            }
                            break;

                        case REQ_VALUE:
                            state = ParseState.REQ_KEY;
                            break;

                        case MACHINE:
                            if (machine != null && login != null && password != null)
                                update0(machine, login, password);
                            machine = match;
                            login = null;
                            password = null;
                            state = ParseState.REQ_KEY;
                            break;

                        case LOGIN:
                            login = match;
                            state = ParseState.REQ_KEY;
                            break;

                        case PASSWORD:
                            password = match;
                            state = ParseState.REQ_KEY;
                            break;

                        case MACDEF:
                            // Only way out is an empty line, handled before the find() loop.
                            break;
                    }
                }
            }
            if (machine != null) {
                if (login != null && password != null) update0(machine, login, password);
            }

        } catch (IOException e) {
            throw new InvalidPropertiesFormatException("Invalid netrc file: '" + this.netrc.getAbsolutePath() + "'");
        }

        return this;
    }

    protected void update0(String machine, String login, String password) {
        Credentials creds = new Credentials(machine, login, password);
        this.hosts.put(
                machine, creds
        );
        if (!this.hosts1.containsKey(machine)) {
            this.hosts1.put(machine, new Stack<>());
        }
        Stack<Credentials> stk = this.hosts1.get(machine);
        stk.push(creds);
    }

    private enum ParseState {
        START, REQ_KEY, REQ_VALUE, MACHINE, LOGIN, PASSWORD, MACDEF, END
    }

}
