package com.aq.userregistration.auth;

import com.aq.userregistration.config.JwtService;
import com.aq.userregistration.user.User;
import com.aq.userregistration.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        System.out.println("AuthenticationService: inside authenticate method");
        System.out.println("Username : "+ request.getEmail() +" & Password: "+ request.getPassword());
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
            )
        );
//        System.out.println("authenticated from authenticationManager: "+request.toString());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
//        System.out.println("fetched user: "+ user.toString());

        String jwtToken = jwtService.generateToken(user);
//        System.out.println(" Token generated: "+jwtToken);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }


}
