package com.aq.userregistration.auth.vo;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

    private String username;
    @JsonProperty("access_token")
    private String accessToken;
    private int accessExpiresIn;

    @JsonProperty("refresh_token")
    private String refreshToken;

}
