package com.dev.app.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * SpringDoc OpenAPI / Swagger UI configuration.
 *
 * URLs (server must be running):
 *   Swagger UI : http://localhost:808/swagger-ui.html
 *   OpenAPI JSON: http://localhost:808/v3/api-docs
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("App Sec Shiro API")
                        .description("Spring Boot 3 + Apache Shiro 2.1 security demo  "
                                + "session-based auth with salted SHA-256 password hashing")
                        .version("1.0.0")
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")));
    }
}
