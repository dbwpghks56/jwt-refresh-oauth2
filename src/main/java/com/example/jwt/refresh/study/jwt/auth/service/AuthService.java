package com.example.jwt.refresh.study.jwt.auth.service;

import com.example.jwt.refresh.study.jwt.auth.dto.request.AccessTokenRefreshRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignInRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignUpRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.response.AccessTokenRefreshResponseDto;
import com.example.jwt.refresh.study.jwt.auth.dto.response.KakaoLoginResponse;
import com.example.jwt.refresh.study.jwt.auth.dto.response.SignInResponseDto;

public interface AuthService {
    SignInResponseDto signIn(SignInRequestDto signInRequestDto) throws Exception;
    Boolean
    signOut(String accessToken) throws Exception;
    Boolean signUpCommon(SignUpRequestDto requestDto) throws Exception;
    Boolean signUpAdmin(SignUpRequestDto requestDto) throws Exception;

    String getUserName(String accessToken) throws Exception;
    AccessTokenRefreshResponseDto accessTokenRefresh(AccessTokenRefreshRequestDto accessTokenRefreshRequestDto);
    KakaoLoginResponse oauthLogin(String code, String requestPath);
}
