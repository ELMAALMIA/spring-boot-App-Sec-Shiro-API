package com.dev.app.config;

import com.dev.app.annotation.CurrentUser;
import com.dev.app.exception.AuthenticationFailedException;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolves {@code @CurrentUser String username} in controller method parameters.
 *
 * <p>Reads the authenticated principal from Shiro's ThreadContext (already bound
 * by {@link ShiroSessionFilter} before the request reaches the controller).</p>
 *
 * <p>Only supports {@code String} parameters annotated with {@link CurrentUser}.
 * Throws {@link AuthenticationFailedException} if no authenticated subject is found.</p>
 *
 * <p>Registered in {@link WebMvcConfig}.</p>
 */
@Component
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CurrentUser.class)
                && parameter.getParameterType().equals(String.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) {
        Subject subject = SecurityUtils.getSubject();
        if (!subject.isAuthenticated()) {
            throw new AuthenticationFailedException("Not authenticated");
        }
        return (String) subject.getPrincipal();
    }
}
