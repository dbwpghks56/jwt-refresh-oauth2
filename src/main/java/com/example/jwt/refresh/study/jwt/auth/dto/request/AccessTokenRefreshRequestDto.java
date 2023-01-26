package com.example.jwt.refresh.study.jwt.auth.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@NoArgsConstructor
public class AccessTokenRefreshRequestDto {
    private String accessToken;
    private String refreshToken;
}
