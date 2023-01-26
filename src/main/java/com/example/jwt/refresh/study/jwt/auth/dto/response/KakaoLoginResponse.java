package com.example.jwt.refresh.study.jwt.auth.dto.response;

import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class KakaoLoginResponse {
    private Long memeberSeq;
    private String nickname;
    private String email;
    private ERole eRole;
    private String tokenType = "Bearer";
    private String accessToken;
    private String refreshToken;

    @Builder
    public KakaoLoginResponse(Long memeberSeq, String nickname, String email, ERole eRole, String accessToken, String refreshToken) {
        this.memeberSeq = memeberSeq;
        this.nickname = nickname;
        this.email = email;
        this.eRole = eRole;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
