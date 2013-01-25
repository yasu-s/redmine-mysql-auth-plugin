package org.jenkinsci.plugins.redmine_mysql_auth.util;

/**
 * @author Yasuyuki Saito
 */
public final class Constants {

    private Constants() {}

    /** MySQL Default DB Server */
    public static final String DEFAULT_DB_SERVER = "127.0.0.1";

    /** MySQL Default DatabaseName */
    public static final String DEFAULT_DATABASE_NAME = "redmine";

    /** MySQL Default Port */
    public static final String DEFAULT_PORT = "3306";

    /** Redmine Version 1.2.0 */
    public static final String VERSION_1_2_0  = "1.2.0";

    /** Redmine Version 1.1.3 */
    public static final String VERSION_1_1_3  = "1.1.3";

    /** Redmine Default Login Table */
    public static final String DEFAULT_LOGIN_TABLE = "users";

    /** Redmine Default User Field */
    public static final String DEFAULT_USER_FIELD = "login";

    /** Redmine Default Password Field */
    public static final String DEFAULT_PASSWORD_FIELD = "hashed_password";

    /** Redmine Default Salt Field */
    public static final String DEFAULT_SALT_FIELD = "salt";


    /** Connection String Format: MySQL */
    public static final String CONNECTION_STRING_FORMAT_MYSQL = "jdbc:mysql://%s:%s/%s";

    /** JDBC Driver Name: MySQL */
    public static final String JDBC_DRIVER_NAME_MYSQL = "com.mysql.jdbc.Driver";

}
