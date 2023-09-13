package com.aq.userregistration.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(
        info = @Info(
                contact = @Contact(
                        name = "Abdul Quadir",
                        email = "abdulquadir01@outlook.com",
                        url = "https://abdulquadir.github.io/2"
                ),
                description = "OpenAPI documentation for Spring Security",
                title = "Auth App - AQ",
                version = "1.0",
                license = @License(
                        name = "Apache2 License",
                        url = "license url from github"
                ),
                termsOfService = "Terms of Service"
        ),
        servers ={
                @Server(
                    description = "local env",
                    url = "http://localhost:8080"
                ),
                @Server(
                    description = "qa env",
                    url = "http://localhost:9090"
                ),
        },
        security = {
                @SecurityRequirement(
                    name="Bearer-Auth"
                )
        }

)

@SecurityScheme(
        name = "Bearer-Auth",
        description = "token based authentication using JWT",
        scheme = "bearer",
        type= SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {
}
