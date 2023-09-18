package com.aq.userregistration;

import com.aq.userregistration.auth.AuthenticationService;
import com.aq.userregistration.auth.vo.RegisterRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.aq.userregistration.user.Role.ADMIN;
import static com.aq.userregistration.user.Role.MANAGER;

@SpringBootApplication
public class UserRegistrationApplication {

	private static final Logger logger = LoggerFactory.getLogger(UserRegistrationApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(UserRegistrationApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService authenticationService){
		logger.info("Adding Test data");

		return  args -> {
			RegisterRequest admin = RegisterRequest.builder()
					.firstName("Admin")
					.lastName("Admin")
					.email("admin@mail.com")
					.password("password")
					.role(ADMIN)
					.build();

			System.out.println("Admin token: "+ authenticationService.register(admin).getAccessToken());

			RegisterRequest manager = RegisterRequest.builder()
					.firstName("Manager")
					.lastName("Manager")
					.email("manager@mail.com")
					.password("password")
					.role(MANAGER)
					.build();

			System.out.println("Manager token: "+ authenticationService.register(manager).getAccessToken());

		};
	}

}
