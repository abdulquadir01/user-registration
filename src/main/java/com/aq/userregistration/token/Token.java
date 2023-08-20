package com.aq.userregistration.token;

import com.aq.userregistration.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", nullable = false)
    private Long id;

    private String accessToken;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    private boolean isExpired;
    private boolean isRevoked;

    private int expiresIn;

    private String refreshToken;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

}
