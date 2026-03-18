package com.dev.app.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

/**
 * Web-layer Shiro wiring.
 *
 * Instead of Shiro's own filter (shiro-web — uses javax.servlet, incompatible
 * with Spring Boot 3.x), we register our own ShiroSessionFilter which uses
 * jakarta.servlet and delegates auth/authz to Shiro's core engine.
 *
 * Also enables @RequiresRoles / @RequiresAuthentication annotations.
 */
@Configuration
public class ShiroWebConfig {

    //  Custom Jakarta-compatible Shiro filter
    @Bean
    public FilterRegistrationBean<ShiroSessionFilter> shiroFilterRegistration(
            DefaultSecurityManager securityManager, ObjectMapper objectMapper) {

        FilterRegistrationBean<ShiroSessionFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new ShiroSessionFilter(securityManager, objectMapper));
        registration.addUrlPatterns("/*");
        registration.setName("shiroFilter");
        registration.setOrder(1);
        return registration;
    }

    //  Manages Shiro bean lifecycle (init & destroy)
    @Bean
    public static LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    //  Creates AOP proxies needed for Shiro annotations
    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    public static DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
        creator.setProxyTargetClass(true);
        return creator;
    }

    //  Activates @RequiresRoles, @RequiresPermissions...
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);
        return advisor;
    }
}
