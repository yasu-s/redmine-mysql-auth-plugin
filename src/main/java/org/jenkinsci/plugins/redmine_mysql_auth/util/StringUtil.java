package org.jenkinsci.plugins.redmine_mysql_auth.util;

/**
 * String Utility
 * @author Yasuyuki Saito
 */
public abstract class StringUtil {

    /**
     *
     * @param value
     * @return
     */
    public static boolean isNullOrEmpty(String value) {
        return (value == null) || "".equals(value);
    }
}
