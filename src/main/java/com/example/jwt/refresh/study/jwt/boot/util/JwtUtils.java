package com.example.jwt.refresh.study.jwt.boot.util;

import com.example.jwt.refresh.study.jwt.auth.domain.model.AuthToken;
import com.example.jwt.refresh.study.jwt.auth.domain.repository.AuthTokenRepository;
import com.example.jwt.refresh.study.jwt.boot.exception.RestException;
//import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsImpl;
import com.example.jwt.refresh.study.jwt.user.service.impl.principal.PrincipalDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtUtils {
    @Value("${jwt.secret}")
    private String jwtSecret;

    private final AuthTokenRepository authTokenRepository;

    public Key getKey()  {
        byte[] keys = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keys);
    }

    public String generateAccessToken(Authentication authentication) {
        PrincipalDetails userDetails = (PrincipalDetails) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + (1000L * 60 * 60)))
                .setIssuer("Tester")
                .signWith(getKey(), SignatureAlgorithm.HS512)
                .claim("name", userDetails.getEmail())
                .compact();
    }

    public String generateRefreshToken(Authentication authentication) {
        PrincipalDetails userDetails = (PrincipalDetails) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + (1000L * 60 * 60)))
                .setIssuer("Tester")
                .signWith(getKey(), SignatureAlgorithm.HS512)
                .claim("name", userDetails.getEmail())
                .compact();
    }

    public String getUserNameFromAccessToken(String token) {
        try{
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getSubject();
        } catch (ExpiredJwtException e) {
            log.warn("만료된 AccessToken 입니다.");
            return e.getClaims().getSubject();
        }
    }

    public String getNameForAccessToken(String token) {
        try{
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return (String) claims.get("name");
        } catch (ExpiredJwtException e) {
            log.warn("만료된 AccessToken 입니다.");
            return e.getClaims().getSubject();
        }
    }

    public String getAccessTokenFromBearer(String rawAccessToken) {
        return rawAccessToken.replace("Bearer ", "");
    }

    public Boolean validateAccessToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token);

            return true;

        } catch (ExpiredJwtException e) {
            log.error("만료된 토큰입니다. msg=" + e.getMessage());
            throw new ExpiredJwtException(null, null, "만료된 토큰입니다. msg=" + e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("지원하지 않는 토큰 형식입니다. msg=" + e.getMessage());
            throw new UnsupportedJwtException("지원하지 않는 토큰 형식입니다. msg=" + e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("유효하지 않는 토큰입니다. msg=" + e.getMessage());
            throw new MalformedJwtException("유효하지 않는 토큰입니다. Refresh Token 을 활용한 재갱신이 필요합니다. msg=" + e.getMessage());
        } catch (SignatureException e) {
            log.error("유효하지 않은 Signature 입니다. msg=" + e.getMessage());
            throw new SignatureException("유효하지 않은 Signature 입니다. msg=" + e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("유효하지 않은 인자입니다. msg=" + e.getMessage());
            throw new IllegalArgumentException("유효하지 않은 인자입니다. msg=" + e.getMessage());
        }
    }

    public Boolean validateRefreshToken(String fakeRefreshToken) {
        AuthToken authTokenEntity = authTokenRepository.findBySeq(fakeRefreshToken)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당하는 RefreshToken을 찾을 수 없습니다."));

        try {
            Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(authTokenEntity.getRefreshToken());

            return true;
        } catch (ExpiredJwtException e) {
            log.warn("만료된 Refresh Token 입니다.");
            return false;
        }
    }
}
