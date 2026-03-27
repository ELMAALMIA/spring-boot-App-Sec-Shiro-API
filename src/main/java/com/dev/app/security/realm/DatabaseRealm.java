package com.dev.app.security.realm;

import com.dev.app.enums.RoleName;
import com.dev.app.repository.UserRepository;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.PasswordService;
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
 * <h3>Timing side-channel prevention</h3>
 * When a username does not exist, a dummy password hash comparison is performed
 * before throwing {@link UnknownAccountException}. This equalizes the response
 * time between "user not found" and "wrong password" paths, preventing
 * username enumeration via timing attacks.
 *
 * <h3>Constructor injection</h3>
 * This bean is instantiated manually in {@code ShiroConfig}, so {@link UserRepository}
 * and {@link PasswordService} are passed via the constructor — no {@code @Autowired}
 * field injection needed.
 */
public class DatabaseRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(DatabaseRealm.class);

    /**
     * A pre-computed dummy hash used to equalize timing when a username is not found.
     * The value is a valid Shiro2 SHA-512 hash format — it will never match any input
     * but forces the same hash computation path as a real credential check.
     */
    private static final String DUMMY_HASH =
            "$shiro2$SHA-512$500000$dummy-salt-for-timing-equalization$dummyhashvalue";

    private final UserRepository userRepository;
    private final PasswordService passwordService;

    public DatabaseRealm(UserRepository userRepository, PasswordService passwordService) {
        this.userRepository  = userRepository;
        this.passwordService = passwordService;
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
                .orElse(null);

        if (user == null) {
            // Equalize timing: perform a dummy hash check so the response time
            // is indistinguishable from a wrong-password attempt, preventing
            // username enumeration via timing side-channel.
            try {
                passwordService.passwordsMatch("dummy-input", DUMMY_HASH);
            } catch (Exception ignored) {
                // The dummy hash will never match — the exception is expected.
            }
            log.warn("Authentication failed — user not found");
            throw new UnknownAccountException("Invalid credentials");
        }

        return new SimpleAuthenticationInfo(
                user.getUsername(),
                user.getPassword(),
                getName()
        );
    }
}
