package com.example.jwt.refresh.study.jwt.auth.dto.response;

import lombok.*;

@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessTokenRefreshResponseDto {
    private String accessToken;
}
