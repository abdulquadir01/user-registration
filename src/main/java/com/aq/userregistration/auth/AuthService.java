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
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    private final TokenRepository  tokenRepository;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        User savedUser = userRepository.save(user);

        String jwtToken = jwtService.generateToken(savedUser);
        String refreshToken = jwtService.generateRefreshToken(savedUser);

        System.out.println("From AuthService  register() ------");
        System.out.println("accessToken: " + jwtToken);
        System.out.println("refreshToken: " +refreshToken);

        Token savedToken = saveUserToken(savedUser, jwtToken, refreshToken);

        return AuthenticationResponse.builder()
                .username(request.getEmail())
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .accessExpiresIn(savedToken.getExpiresIn())
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try{
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
            );
        }catch (Exception e){
            e.getStackTrace();
        }

        User user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        System.out.println("From AuthService  authenticate() ------");
        System.out.println("accessToken: " + jwtToken);
        System.out.println("refreshToken: " +refreshToken);

        revokeAllUserTokens(user);
//  first we revoke the existing tokens of a user then assign a new one which has not been revoked.
        Token savedToken = saveUserToken(user, jwtToken, refreshToken);

        return AuthenticationResponse.builder()
                .username(request.getEmail())
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .accessExpiresIn(savedToken.getExpiresIn())
                .build();
    }

    private void revokeAllUserTokens(User user){
        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());

        if(validUserTokens.isEmpty()){
            return;
        }

        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }


    private Token saveUserToken(User user, String jwtToken, String refreshToken) {
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

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }

        refreshToken = authHeader.substring(7);
//      extract the userEmail from JWT Token
        userEmail = jwtService.extractUsername(refreshToken);

        if(userEmail != null){
            User user = this.userRepository.findByEmail(userEmail).orElseThrow();

//          cross-check the validity of refreshToken from DB
//          Boolean isTokenValid = tokenRepository.findByRefreshToken(refreshToken)
//                    .map(token -> !token.isExpired() && !token.isRevoked())
//                    .orElse(false);

            if(jwtService.isTokenValid(refreshToken, user)){
               String accessToken = jwtService.generateToken(user);
               AuthenticationResponse authResponse = AuthenticationResponse.builder()
                       .username(userEmail)
                       .accessExpiresIn(AppConstants.TOKEN_VALIDITY_IN_SEC)
                       .accessToken(accessToken)
                       .refreshToken(refreshToken)
                       .build();

               revokeAllUserTokens(user);
               saveUserToken(user, accessToken, refreshToken);

               new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
