package com.dev.app.security.realm;

import com.dev.app.enums.RoleName;
import com.dev.app.repository.UserRepository;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Custom Shiro Realm — bridges Shiro with the database.
 *
 * <ul>
 *   <li>{@link #doGetAuthenticationInfo} — called on {@code Subject.login()} to verify credentials</li>
 *   <li>{@link #doGetAuthorizationInfo}  — called on role/permission checks to load roles + permissions</li>
 * </ul>
 *
 * <h3>Permission model</h3>
 * <ul>
 *   <li>{@link RoleName#ADMIN} → {@code admin:*}, {@code user:*}</li>
 *   <li>{@link RoleName#USER}  → {@code user:read}, {@code user:profile}</li>
 * </ul>
 *
 * <h3>Constructor injection</h3>
 * This bean is instantiated manually in {@code ShiroConfig}, so {@link UserRepository}
 * is passed via the constructor — no {@code @Autowired} field injection needed.
 */
public class DatabaseRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(DatabaseRealm.class);

    private final UserRepository userRepository;

    public DatabaseRealm(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Load roles and Shiro wildcard permissions for the authenticated user.
     * Uses {@link RoleName} enum — no raw string literals.
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        log.debug("Loading roles/permissions for user '{}'", username);

        com.dev.app.entities.User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UnknownAccountException("User not found: " + username));

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        user.getRoles().forEach(role -> {
            info.addRole(role.getName().name());
            log.debug("  role: {}", role.getName());

            if (role.getName() == RoleName.ADMIN) {
                info.addStringPermission("admin:*");
                info.addStringPermission("user:*");
            } else if (role.getName() == RoleName.USER) {
                info.addStringPermission("user:read");
                info.addStringPermission("user:profile");
            }
        });

        return info;
    }

    /**
     * Verify login credentials against the stored hash.
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {

        String username = (String) token.getPrincipal();
        log.debug("Authenticating user '{}'", username);

        com.dev.app.entities.User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("Authentication failed — user not found");
                    return new UnknownAccountException("Invalid credentials");
                });

        return new SimpleAuthenticationInfo(
                user.getUsername(),
                user.getPassword(),
                getName()
        );
    }
}
