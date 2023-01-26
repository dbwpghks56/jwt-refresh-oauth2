package com.example.jwt.refresh.study.jwt.auth.oauth.provider;

import com.example.jwt.refresh.study.jwt.auth.oauth.OAuth2UserInfo;

import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo {
    private Map<String, Object> attributes;

    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getProvider() {
        return "Naver";
    }

    @Override
    public String getEmail() {
        return getNaverAccount().get("email").toString();
    }

    @Override
    public String getNickName() {
        return getNaverAccount().get("name").toString();
    }

    public Map<String, Object> getNaverAccount() {
        return (Map<String, Object>) attributes.get("response");
    }
}
