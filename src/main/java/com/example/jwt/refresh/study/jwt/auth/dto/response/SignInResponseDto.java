package com.example.jwt.refresh.study.jwt.auth.dto.response;

import lombok.*;

import java.util.Set;

@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignInResponseDto {
    private String accessToken;
    private String refreshToken;
    private String type = "Bearer";
    private Long userSeq;
    private String username;
    private Set<String> roles;
}
