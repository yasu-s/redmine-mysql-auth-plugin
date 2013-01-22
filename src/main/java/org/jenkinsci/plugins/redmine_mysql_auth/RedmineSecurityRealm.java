package org.jenkinsci.plugins.redmine_mysql_auth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jenkinsci.plugins.redmine_mysql_auth.util.CipherUtil;
import org.jenkinsci.plugins.redmine_mysql_auth.util.StringUtil;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

/**
 *
 * @author Yasuyuki Saito
 */
public class RedmineSecurityRealm extends AbstractPasswordBasedSecurityRealm {

    /** MySQL Default DB Server */
    private static final String DEFAULT_DB_SERVER = "127.0.0.1";

    /** MySQL Default DatabaseName */
    private static final String DEFAULT_DATABASE_NAME = "redmine";

    /** MySQL Default Port */
    private static final String DEFAULT_PORT = "3306";

    /** Redmine Version 1.2.0 */
    private static final String VERSION_1_2_0  = "1.2.0";

    /** Redmine Version 1.1.3 */
    private static final String VERSION_1_1_3  = "1.1.3";

    /** Redmine Default Login Table */
    private static final String DEFAULT_LOGIN_TABLE = "users";

    /** Redmine Default User Field */
    private static final String DEFAULT_USER_FIELD = "login";

    /** Redmine Default Password Field */
    private static final String DEFAULT_PASSWORD_FIELD = "hashed_password";

    /** Redmine Default Salt Field */
    private static final String DEFAULT_SALT_FIELD = "salt";

    /** Connection String Format: MySQL */
    private static final String CONNECTION_STRING_FORMAT_MYSQL = "jdbc:mysql://%s:%s/%s";

    /** JDBC Driver Name: MySQL */
    private static final String JDBC_DRIVER_NAME_MYSQL = "com.mysql.jdbc.Driver";

    /** Logger */
    private static final Logger LOGGER = Logger.getLogger(RedmineSecurityRealm.class.getName());

    /** DB Server */
    private final String dbServer;

    /** Database Name */
    private final String databaseName;

    /** Database Port */
    private final String port;

    /** Database UserName */
    private final String dbUserName;

    /** Database Password */
    private final String dbPassword;

    /** Redmine Version */
    private final String version;

    /** Redmine Login Table */
    private final String loginTable;

    /** Redmine User Field */
    private final String userField;

    /** Redmine Password Field */
    private final String passField;

    /** Redmine Salt Field */
    private final String saltField;


    /**
     * Constructor
     * @param dbServer DB Server
     * @param databaseName Database Name
     * @param port Database Port
     * @param dbUserName Database UserName
     * @param dbPassword Redmine Version
     * @param version Redmine Version
     * @param loginTable Redmine Login Table
     * @param userField Redmine User Field
     * @param passField Redmine Password Field
     * @param saltField Redmine Salt Field
     */
    @DataBoundConstructor
    public RedmineSecurityRealm(String dbServer, String databaseName, String port, String dbUserName, String dbPassword,
            String version, String loginTable, String userField, String passField, String saltField) {

        this.dbServer     = StringUtil.isNullOrEmpty(dbServer)     ? DEFAULT_DB_SERVER       : dbServer;
        this.databaseName = StringUtil.isNullOrEmpty(databaseName) ? DEFAULT_DATABASE_NAME   : databaseName;
        this.port         = StringUtil.isNullOrEmpty(port)         ? DEFAULT_PORT            : port;
        this.dbUserName   = dbUserName;
        this.dbPassword   = dbPassword;
        this.version      = StringUtil.isNullOrEmpty(version)      ? VERSION_1_2_0           : version;

        this.loginTable   = StringUtil.isNullOrEmpty(loginTable)   ? DEFAULT_LOGIN_TABLE     : loginTable;
        this.userField    = StringUtil.isNullOrEmpty(userField)    ? DEFAULT_USER_FIELD      : userField;
        this.passField    = StringUtil.isNullOrEmpty(passField)    ? DEFAULT_PASSWORD_FIELD  : passField;
        this.saltField    = StringUtil.isNullOrEmpty(saltField)    ? DEFAULT_SALT_FIELD      : saltField;
    }

    /**
     *
     * @author Yasuyuki Saito
     */
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getHelpFile() {
            return "/plugin/redmine-mysql-auth/help/overview.html";
        }

        @Override
        public String getDisplayName() {
            return Messages.RedmineSecurityRealm_DisplayName();
        }
    }

    @Extension
    public static DescriptorImpl install() {
        return new DescriptorImpl();
    }

    /**
     *
     * @author Yasuyuki Saito
     */
    class Authenticator extends AbstractUserDetailsAuthenticationProvider {
        @Override
        protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        }

        @Override
        protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
            return RedmineSecurityRealm.this.authenticate(username, authentication.getCredentials().toString());
        }
    }

    /**
     *
     * @param username Login UserName
     * @param password Login Password
     */
    @Override
    protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        Connection conn = null;

        try {
            conn = getConnection();

            if (!isLoginTable(conn))
                throw new RedmineAuthenticationException("RedmineSecurity: Invalid Login Table -");

            if (!isUserField(conn))
                throw new RedmineAuthenticationException("RedmineSecurity: Invalid User Field -");

            RedmineUserData userData = getRedmineUserData(conn, username);

            if (userData == null) {
                LOGGER.warning("RedmineSecurity: Invalid Username");
                throw new UsernameNotFoundException("RedmineSecurity: User not found");
            }

            String encryptedPassword = "";
            if (VERSION_1_2_0.equals(version)) {
                encryptedPassword = CipherUtil.encodeSHA1(userData.getSalt() + CipherUtil.encodeSHA1(password));
            } else if (VERSION_1_1_3.equals(version)) {
                encryptedPassword =  CipherUtil.encodeSHA1(password);
            }
            LOGGER.info("Redmine Version   : " + version);
            LOGGER.info("Encrypted Password: " + encryptedPassword);

            if (!userData.getPassword().equals(encryptedPassword)) {
                LOGGER.warning("RedmineSecurity: Invalid Password");
                throw new RedmineAuthenticationException("RedmineSecurity: Invalid Password -");
            }

            return getUserDetails(username, userData.getPassword());
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new RedmineAuthenticationException("RedmineSecurity: System.Exception", e);
        } finally {
            if (conn != null) {
                try { conn.close(); } catch (Exception e) {}
            }
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        Connection conn = null;

        try {
            conn = getConnection();

            if (!isLoginTable(conn))
                throw new RedmineAuthenticationException("RedmineSecurity: Invalid Login Table -");

            if (!isUserField(conn))
                throw new RedmineAuthenticationException("RedmineSecurity: Invalid User Field -");

            RedmineUserData userData = getRedmineUserData(conn, username);

            if (userData == null) {
                LOGGER.warning("RedmineSecurity: Invalid Username");
                throw new UsernameNotFoundException("RedmineSecurity: User not found");
            }

            return getUserDetails(username, userData.getPassword());
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new RedmineAuthenticationException("RedmineSecurity: System.Exception", e);
        } finally {
            if (conn != null) {
                try { conn.close(); } catch (Exception e) {}
            }
        }
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupname) throws UsernameNotFoundException, DataAccessException {
        throw new UsernameNotFoundException("RedmineSecurityRealm: Non-supported function");
    }


    /**
     *
     * @return
     * @throws RedmineAuthenticationException
     */
    private Connection getConnection() throws RedmineAuthenticationException {
        Connection conn = null;

        try {
            String connectionString = String.format(CONNECTION_STRING_FORMAT_MYSQL, this.dbServer, this.port, this.databaseName);
            LOGGER.info("RedmineSecurity: Connection String - " + connectionString);

            Class.forName(JDBC_DRIVER_NAME_MYSQL).newInstance();
            conn = DriverManager.getConnection(connectionString, this.dbUserName, this.dbPassword);

            LOGGER.info("RedmineSecurity: Connection established.");

            return conn;
        } catch (SQLException e) {
            throw new RedmineAuthenticationException("RedmineSecurity: Connection Error", e);
        } catch (Exception e) {
            throw new RedmineAuthenticationException("RedmineSecurity: Connection Error", e);
        }
    }

    /**
     * LoginTable Check
     * @param conn
     * @return
     * @throws RedmineAuthenticationException
     */
    private boolean isLoginTable(Connection conn) throws RedmineAuthenticationException {
        PreparedStatement state = null;
        ResultSet results = null;

        try {
            String query = "SHOW TABLES";
            state = conn.prepareStatement(query);
            results = state.executeQuery();

            if (results == null)
                return false;

            while (results.next()) {
                if (results.getString(1).equals(this.loginTable))
                    return true;
            }

            return false;
        } catch (RedmineAuthenticationException e) {
            throw e;
        } catch (SQLException e) {
            throw new RedmineAuthenticationException("RedmineSecurity: LoginTable Check Error", e);
        } catch (Exception e) {
            throw new RedmineAuthenticationException("RedmineSecurity: LoginTable Check Error", e);
        } finally {
            if (results != null) {
                try { results.close(); } catch (Exception e) {}
            }
            if (state != null) {
                try { state.close(); } catch (Exception e) {}
            }
        }
    }

    /**
     * UserField Check
     * @param conn
     * @return
     * @throws RedmineAuthenticationException
     */
    private boolean isUserField(Connection conn) throws RedmineAuthenticationException {
        PreparedStatement state = null;
        ResultSet results = null;

        try {
            String query = String.format("SHOW FIELDS FROM %s", this.loginTable);
            state = conn.prepareStatement(query);
            results = state.executeQuery();

            if (results == null)
                return false;

            while (results.next()) {
                if (results.getString(1).equals(this.userField))
                    return true;
            }

            return false;
        } catch (RedmineAuthenticationException e) {
            throw e;
        } catch (SQLException e) {
            throw new RedmineAuthenticationException("RedmineSecurity: Table Check Error", e);
        } catch (Exception e) {
            throw new RedmineAuthenticationException("RedmineSecurity: Table Check Error", e);
        } finally {
            if (results != null) {
                try { results.close(); } catch (Exception e) {}
            }
            if (state != null) {
                try { state.close(); } catch (Exception e) {}
            }
        }
    }

    /**
     *
     * @param username
     * @return
     * @throws RedmineAuthenticationException
     */
    private RedmineUserData getRedmineUserData(Connection conn, String username) throws RedmineAuthenticationException {
        PreparedStatement state = null;
        ResultSet results = null;

        try {
            String query = String.format("SELECT * FROM %s WHERE %s = ?", this.loginTable, this.userField);

            state = conn.prepareStatement(query);
            state.setString(1, username);

            LOGGER.info("RedmineSecurity: Query Info - " + query);
            LOGGER.info("- Username: " + username);
            results = state.executeQuery();
            LOGGER.info("RedmineSecurity: Query executed.");

            if (results == null)
                return null;

            if (results.first()) {
                RedmineUserData userData = new RedmineUserData();
                userData.setUsername(results.getString(this.userField));
                userData.setPassword(results.getString(this.passField));

                if (VERSION_1_2_0.equals(version))
                    userData.setSalt(results.getString(this.saltField));

                return userData;
            } else
                return null;
        } catch (RedmineAuthenticationException e) {
            throw e;
        } catch (SQLException e) {
            throw new RedmineAuthenticationException("RedmineSecurity: Query Error", e);
        } catch (Exception e) {
            throw new RedmineAuthenticationException("RedmineSecurity: Query Error", e);
        } finally {
            if (results != null) {
                try { results.close(); } catch (Exception e) {}
            }
            if (state != null) {
                try { state.close(); } catch (Exception e) {}
            }
        }
    }

    /**
     *
     * @param username
     * @param password
     * @return
     */
    private UserDetails getUserDetails(String username, String password) {
        Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
        groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        return new RedmineUserDetails(username, password, true, true, true, true, groups.toArray(new GrantedAuthority[groups.size()]));
    }


    /**
     *
     * @return
     */
    public String getDbServer() {
        return dbServer;
    }

    /**
     *
     * @return
     */
    public String getDatabaseName() {
        return databaseName;
    }

    /**
     *
     * @return
     */
    public String getPort() {
        return port;
    }

    /**
     *
     * @return
     */
    public String getDbUserName() {
        return dbUserName;
    }

    /**
     *
     * @return
     */
    public String getDbPassword() {
        return dbPassword;
    }

    /**
     *
     * @return
     */
    public String getVersion() {
        return version;
    }

    /**
     *
     * @return
     */
    public String getLoginTable() {
        return loginTable;
    }

    /**
     *
     * @return
     */
    public String getUserField() {
        return userField;
    }

    /**
     *
     * @return
     */
    public String getPassField() {
        return passField;
    }

    /**
     *
     * @return
     */
    public String getSaltField() {
        return saltField;
    }
}
