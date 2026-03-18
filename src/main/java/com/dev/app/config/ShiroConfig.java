package com.dev.app.config;

import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Core Shiro configuration — no servlet/web dependency.
 *
 * Why DefaultSecurityManager (not DefaultWebSecurityManager)?
 *   DefaultWebSecurityManager is in shiro-web which still uses javax.servlet
 *   and cannot compile/run on Spring Boot 3.x (jakarta.servlet).
 *   We use DefaultSecurityManager from shiro-core (no servlet dependency)
 *   and handle the web/session layer ourselves in ShiroSessionFilter.
 *
 * Password Hashing Strategy (Shiro 2.x DefaultPasswordService defaults):
 *   - Algorithm : SHA-512
 *   - Iterations: 50 000
 *   - Salt      : random per-user, auto-generated and stored in $shiro2$ hash string
 *   PasswordMatcher delegates to DefaultPasswordService for verification,
 *   which parses the $shiro2$ format to extract algorithm, iterations and salt.
 *
 * Beans:
 *  1. DefaultPasswordService — hashes and verifies passwords
 *  2. PasswordMatcher        — credential comparator for the Realm
 *  3. DatabaseRealm          — loads users + roles from the database
 *  4. DefaultSecurityManager — Shiro's central security coordinator
 */
@Configuration
public class ShiroConfig {

    //  1. Password service (hashing + verification)
    @Bean
    public DefaultPasswordService passwordService() {
        return new DefaultPasswordService();
    }

    //  2. PasswordMatcher : wraps PasswordService for Shiro credential check
    @Bean
    public PasswordMatcher credentialsMatcher(DefaultPasswordService passwordService) {
        PasswordMatcher matcher = new PasswordMatcher();
        matcher.setPasswordService(passwordService);
        return matcher;
    }

    //  3. Custom Realm (loads users/roles )
    @Bean
    public DatabaseRealm databaseRealm(PasswordMatcher credentialsMatcher) {
        DatabaseRealm realm = new DatabaseRealm();
        realm.setCredentialsMatcher(credentialsMatcher);
        return realm;
    }

    //  4. SecurityManager
    @Bean
    public DefaultSecurityManager securityManager(DatabaseRealm databaseRealm) {
        return new DefaultSecurityManager(databaseRealm);
    }
}
