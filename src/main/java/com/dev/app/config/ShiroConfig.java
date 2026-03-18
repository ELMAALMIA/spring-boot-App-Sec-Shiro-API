package com.dev.app.config;

import com.dev.app.repository.UserRepository;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Core Shiro configuration — no servlet/web dependency.
 *
 * <h3>Why DefaultSecurityManager (not DefaultWebSecurityManager)?</h3>
 * {@code DefaultWebSecurityManager} is in {@code shiro-web}, which still uses
 * {@code javax.servlet} and cannot compile on Spring Boot 3.x ({@code jakarta.servlet}).
 * We use {@code DefaultSecurityManager} from {@code shiro-core} (no servlet dependency)
 * and handle the web/session layer in {@link ShiroSessionFilter}.
 *
 * <h3>Password hashing (Shiro 2.x defaults)</h3>
 * Algorithm: SHA-512 · Iterations: 50 000 · Salt: random per-user (auto-generated).
 * Stored as {@code $shiro2$SHA-512$50000$<base64-salt>$<base64-hash>}.
 *
 * <h3>Constructor injection</h3>
 * {@link DatabaseRealm} is instantiated here and receives {@link UserRepository}
 * via its constructor — no {@code @Autowired} field injection on the realm.
 *
 * <p>Beans:</p>
 * <ol>
 *   <li>{@link DefaultPasswordService}  — hashes and verifies passwords</li>
 *   <li>{@link PasswordMatcher}         — credential comparator for the Realm</li>
 *   <li>{@link DatabaseRealm}           — loads users + roles from the database</li>
 *   <li>{@link DefaultSecurityManager}  — Shiro's central security coordinator</li>
 * </ol>
 */
@Configuration
public class ShiroConfig {

    @Bean
    public DefaultPasswordService passwordService() {
        return new DefaultPasswordService();
    }

    @Bean
    public PasswordMatcher credentialsMatcher(DefaultPasswordService passwordService) {
        PasswordMatcher matcher = new PasswordMatcher();
        matcher.setPasswordService(passwordService);
        return matcher;
    }

    /**
     * {@link UserRepository} is injected by Spring as a bean method parameter —
     * constructor injection without {@code @Autowired} on the realm class.
     */
    @Bean
    public DatabaseRealm databaseRealm(PasswordMatcher credentialsMatcher,
                                        UserRepository userRepository) {
        DatabaseRealm realm = new DatabaseRealm(userRepository);
        realm.setCredentialsMatcher(credentialsMatcher);
        return realm;
    }

    @Bean
    public DefaultSecurityManager securityManager(DatabaseRealm databaseRealm) {
        return new DefaultSecurityManager(databaseRealm);
    }
}
