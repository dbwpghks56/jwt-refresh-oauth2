package com.example.jwt.refresh.study.jwt.auth.domain.repository;

import com.example.jwt.refresh.study.jwt.auth.domain.model.AuthToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AuthTokenRepository extends JpaRepository<AuthToken, String> {
    Optional<AuthToken> findBySeq(String fakeRefreshToken );
    void deleteBySeq(String fakeRefreshToken);
    void deleteByUserSeq(Long userSeq);
    Integer deleteByAccessToken(String accessToken);
    Integer deleteByUserSeqIn(List<Long> userSeqList);
    Boolean existsBySeq(String fakeRefreshToken);
    Boolean existsByUserSeq(Long userSeq);
    Boolean existsByAccessToken(String accessToken);
    Boolean existsByAccessTokenAndSeq(String accessToken, String fakeRefreshToken);
}
