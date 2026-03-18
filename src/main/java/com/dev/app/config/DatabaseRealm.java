package com.dev.app.config;

import com.dev.app.entities.User;
import com.dev.app.repository.UserRepository;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Custom Shiro Realm — bridges Shiro with the database.
 *
 * <ul>
 *   <li>{@code doGetAuthenticationInfo} — called on {@code Subject.login()} to verify credentials</li>
 *   <li>{@code doGetAuthorizationInfo}  — called on role/permission checks to load user roles</li>
 * </ul>
 *
 * <p>Note: Uses {@code @Autowired} field injection because this bean is created manually
 * in {@link ShiroConfig} (not auto-detected via component scanning). Spring injects
 * the {@link UserRepository} after construction.</p>
 */
public class DatabaseRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(DatabaseRealm.class);

    @Autowired
    private UserRepository userRepository;

    /**
     * Load roles for the authenticated user.
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        log.debug("Loading roles for user '{}'", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UnknownAccountException("User not found: " + username));

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        user.getRoles().forEach(role -> {
            String roleName = role.getName().name();
            info.addRole(roleName);
            log.debug("  role: {}", roleName);
        });

        return info;
    }

    /**
     * Verify login credentials.
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {

        String username = (String) token.getPrincipal();
        log.debug("Authenticating user '{}'", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("Authentication failed — unknown user: {}", username);
                    return new UnknownAccountException("Unknown user: " + username);
                });

        return new SimpleAuthenticationInfo(
                user.getUsername(),   // principal stored in session
                user.getPassword(),   // stored hashed password
                getName()             // realm name
        );
    }
}
