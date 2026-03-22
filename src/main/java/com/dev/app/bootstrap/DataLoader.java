package com.dev.app.bootstrap;

import com.dev.app.entities.Role;
import com.dev.app.enums.RoleName;
import com.dev.app.entities.User;
import com.dev.app.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

/**
 * Seeds the database with test users on every startup.
 * Runs automatically because it implements {@link CommandLineRunner}.
 *
 * <p>Users created:</p>
 * <ul>
 *   <li>admin / admin123 — roles: ADMIN + USER</li>
 *   <li>ayoub / ayoub123 — roles: USER</li>
 * </ul>
 *
 * <p>Passwords are stored using {@link DefaultPasswordService} which produces
 * a {@code $shiro2$SHA-512$50000$<salt>$<hash>} string — salted + iterated,
 * safe against rainbow-table and brute-force attacks.</p>
 *
 * <p>Only active when {@code app.seed-test-users=true} in application properties.</p>
 */
@Component
@ConditionalOnProperty(name = "app.seed-test-users", havingValue = "true")
public class DataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataLoader.class);

    private final UserRepository userRepository;
    private final DefaultPasswordService passwordService;

    @PersistenceContext
    private EntityManager em;

    public DataLoader(UserRepository userRepository, DefaultPasswordService passwordService) {
        this.userRepository = userRepository;
        this.passwordService = passwordService;
    }

    @Override
    @Transactional
    public void run(String... args) {
        log.info("Seeding test users ...");

        // Create roles
        Role adminRole = createRole(RoleName.ADMIN);
        Role userRole  = createRole(RoleName.USER);

        // Create users
        createUser("admin", "Admin123!", Set.of(adminRole, userRole));
        createUser("ayoub", "Ayoub123!", Set.of(userRole));

        log.info("Test users seeded: admin/Admin123! (ADMIN,USER) — ayoub/Ayoub123! (USER)");
    }

    private Role createRole(RoleName name) {
        Role role = new Role();
        role.setName(name);
        em.persist(role);
        log.debug("Role created: {}", name);
        return role;
    }

    private void createUser(String username, String rawPassword, Set<Role> roles) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordService.encryptPassword(rawPassword));
        user.setRoles(roles);
        userRepository.save(user);
        log.debug("User created: {} with roles {}", username,
                roles.stream().map(r -> r.getName().name()).toList());
    }
}
