package co.cdjones.security.auth;

/**
 * @author chrisjones
 * @date 11/10/2017
 */
public class Credentials {

    public Credentials(String host, String user, String password) {
        this.user = user;
        this.password = password;
        this.host = host;
    }
    private String user;
    private String password;
    private String host;

    public String user() {
        return user;
    }

    public String password() {
        return password;
    }

    public String host() {
        return host;
    }

    public String toString() {
        return String.format("Credentials: %s %s %s", host, user, password);
    }
}
