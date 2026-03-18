package com.dev.app.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public health-check / greeting endpoint.
 * No authentication required (listed in ShiroSessionFilter.ANON_PATHS).
 */
@RestController
@RequestMapping("/api/v1")
public class HelloController {

    /**
     * GET /api/v1/hello — public, no auth needed.
     */
    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }
}
