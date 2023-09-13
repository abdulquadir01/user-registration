package com.aq.userregistration.controller;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


/*
 * @Hidden - can be used at class level as well as method level.
 * @Hidden - this hides the method from being displayed on Swagger-UI
 * */

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @GetMapping()
    @PreAuthorize("hasAuthority('admin:read')")
    public String get() {
        return "GET: admin controller";
    }
    @PostMapping()
    @PreAuthorize("hasAuthority('admin:create')")
    @Hidden
    public String post() {
        return "POST: admin controller";
    }
    @PutMapping()
    @PreAuthorize("hasAuthority('admin:update')")
    @Hidden
    public String put() {
        return "PUT: admin controller";
    }
    @DeleteMapping()
    @PreAuthorize("hasAuthority('admin:delete')")
    @Hidden
    public String delete() {
        return "DELETE: admin controller";
    }

}