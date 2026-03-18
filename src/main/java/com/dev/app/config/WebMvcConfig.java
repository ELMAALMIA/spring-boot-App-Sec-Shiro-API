package com.dev.app.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * Spring MVC configuration.
 *
 * <p>Registers:</p>
 * <ul>
 *   <li>{@link CurrentUserArgumentResolver} — resolves {@code @CurrentUser String username}</li>
 *   <li>{@link RateLimitInterceptor}         — enforces {@code @RateLimit} on annotated endpoints</li>
 * </ul>
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final CurrentUserArgumentResolver currentUserResolver;
    private final RateLimitInterceptor rateLimitInterceptor;

    public WebMvcConfig(CurrentUserArgumentResolver currentUserResolver,
                        RateLimitInterceptor rateLimitInterceptor) {
        this.currentUserResolver = currentUserResolver;
        this.rateLimitInterceptor = rateLimitInterceptor;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(currentUserResolver);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitInterceptor);
    }
}
