package com.dev.app.config;

import com.dev.app.repository.UserRepository;
import com.dev.app.security.realm.DatabaseRealm;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
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
 * <h3>Authorization cache</h3>
 * {@link MemoryConstrainedCacheManager} is wired into the
 * {@link DefaultSecurityManager} so that Shiro caches each user's roles
 * and permissions after the first {@code doGetAuthorizationInfo()} call.
 * Without a cache, every {@code subject.hasRole()} / {@code isPermitted()}
 * triggers a fresh database query — one per AOP annotation per request.
 *
 * <p>Beans:</p>
 * <ol>
 *   <li>{@link DefaultPasswordService}       — hashes and verifies passwords</li>
 *   <li>{@link PasswordMatcher}              — credential comparator for the Realm</li>
 *   <li>{@link DatabaseRealm}               — loads users + roles from the database</li>
 *   <li>{@link MemoryConstrainedCacheManager}— in-process auth cache (bounded memory)</li>
 *   <li>{@link DefaultSecurityManager}       — Shiro's central security coordinator</li>
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
                                        DefaultPasswordService passwordService,
                                        UserRepository userRepository) {
        DatabaseRealm realm = new DatabaseRealm(userRepository, passwordService);
        realm.setCredentialsMatcher(credentialsMatcher);
        return realm;
    }

    /**
     * Bounded in-memory cache for Shiro authorization data.
     *
     * <p>Caches the result of {@code doGetAuthorizationInfo()} per principal,
     * eliminating repeated DB queries on every role/permission check.
     * For clustered deployments replace with an EhCache or Redis-backed
     * {@code CacheManager}.</p>
     */
    @Bean
    public MemoryConstrainedCacheManager shiroCacheManager() {
        return new MemoryConstrainedCacheManager();
    }

    @Bean
    public DefaultSecurityManager securityManager(DatabaseRealm databaseRealm,
                                                   MemoryConstrainedCacheManager cacheManager) {
        DefaultSecurityManager sm = new DefaultSecurityManager(databaseRealm);
        sm.setCacheManager(cacheManager);
        return sm;
    }
}
