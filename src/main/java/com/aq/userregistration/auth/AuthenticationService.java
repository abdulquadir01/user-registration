package com.aq.userregistration.auth;

import com.aq.userregistration.auth.vo.AuthenticationRequest;
import com.aq.userregistration.auth.vo.AuthenticationResponse;
import com.aq.userregistration.auth.vo.RegisterRequest;
import com.aq.userregistration.constant.AppConstants;
import com.aq.userregistration.config.JwtService;
import com.aq.userregistration.token.Token;
import com.aq.userregistration.token.TokenRepository;
import com.aq.userregistration.token.TokenType;
import com.aq.userregistration.user.User;
import com.aq.userregistration.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository  tokenRepository;

    public AuthenticationResponse register(RegisterRequest request) {
        logger.info("Inside AuthenticationService -> register()");

        User user = User.builder()
                    .id(1L)
                    .firstName(request.getFirstName())
                    .lastName(request.getLastName())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role(request.getRole())
                    .build();
        logger.info("Saving new user to db");
        logger.info("User: {}", user);
        User savedUser = userRepository.save(user);

        logger.info("Generating Access Token");
        String jwtToken = jwtService.generateToken(savedUser);
        logger.info("accessToken: {}", jwtToken);
        logger.info("Generating Refresh Token");
        String refreshToken = jwtService.generateRefreshToken(savedUser);
        logger.info("refreshToken: {}", refreshToken);

//        System.out.println("From AuthService  register() ------");
//        System.out.println("accessToken: " + jwtToken);
//        System.out.println("refreshToken: " +refreshToken);

        Token savedToken = saveUserToken(savedUser, jwtToken, refreshToken);
        logger.info("Token saved in db");

        return AuthenticationResponse.builder()
                .username(request.getEmail())
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .accessExpiresIn(savedToken.getExpiresIn())
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        logger.info("Inside AuthenticationService -> authenticate()");
        try{
            logger.info("Authentication Request payload: {}", request);
            authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
            );
        }catch (Exception e){
            e.getStackTrace();
        }
        logger.info("retrieving  user info after extracting mail id from request");
        User user = userRepository.findByEmail(request.getEmail())
                        .orElseThrow();

        logger.info("generating access token");
        String jwtToken = jwtService.generateToken(user);
        logger.info("generating refresh token");
        String refreshToken = jwtService.generateRefreshToken(user);

//        System.out.println("From AuthService  authenticate() ------");
//        System.out.println("accessToken: " + jwtToken);
//        System.out.println("refreshToken: " +refreshToken);
        logger.info("revoking previous tokens");
        revokeAllUserTokens(user);

        logger.info("saving the new access & refresh tokens to db");
//        first we revoke the existing tokens of a user then assign a new one which has not been revoked.
        Token savedToken = saveUserToken(user, jwtToken, refreshToken);

        AuthenticationResponse authenticationResponse = AuthenticationResponse.builder()
                .username(request.getEmail())
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .accessExpiresIn(savedToken.getExpiresIn())
                .build();
        logger.info("Returning authentication response {}", authenticationResponse);
        return authenticationResponse;
    }

    private Token saveUserToken(User user, String jwtToken, String refreshToken) {
        logger.info("Saving access & refresh token for user: {}", user);
        Token token = Token.builder()
                .user(user)
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .tokenType(TokenType.BEARER)
                .isRevoked(false)
                .isExpired(false)
                .expiresIn(AppConstants.TOKEN_VALIDITY_IN_SEC)
                .build();
        return tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user){
        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());


        if(validUserTokens.isEmpty()){
        logger.info("No prior access &/or refresh token exists for user: {}", user);
            return;
        }

        logger.info("Revoking all access & refresh token for user: {}", user);
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            logger.info("Auth token not found in the HTTP Header");
            return;
        }

        refreshToken = authHeader.substring(7);
        logger.info("extracting username from refresh-token");
//      extract the userEmail from JWT Token
        userEmail = jwtService.extractUsername(refreshToken);

        if(userEmail != null){

            User user = this.userRepository.findByEmail(userEmail).orElseThrow();

//          cross-check the validity of refreshToken from DB
//          Boolean isTokenValid = tokenRepository.findByRefreshToken(refreshToken)
//                    .map(token -> !token.isExpired() && !token.isRevoked())
//                    .orElse(false);
            logger.info("checking the validity of refresh-token");
            if(jwtService.isTokenValid(refreshToken, user)){
               String accessToken = jwtService.generateToken(user);
               AuthenticationResponse authResponse = AuthenticationResponse.builder()
                       .username(userEmail)
                       .accessExpiresIn(AppConstants.TOKEN_VALIDITY_IN_SEC)
                       .accessToken(accessToken)
                       .refreshToken(refreshToken)
                       .build();
                logger.info("Revoking all prior access token before assigning new ones");
               revokeAllUserTokens(user);
               saveUserToken(user, accessToken, refreshToken);
                logger.info("writing authentication response to HttpServletResponse Object");
               new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
