package com.example.jwt.refresh.study.jwt.auth.oauth;

public interface OAuth2UserInfo {
    String getProviderId();
    String getProvider();
    String getEmail();
    String getNickName();
}
