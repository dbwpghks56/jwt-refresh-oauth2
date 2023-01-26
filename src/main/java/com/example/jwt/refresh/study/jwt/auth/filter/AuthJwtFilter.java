package com.example.jwt.refresh.study.jwt.auth.filter;

import com.example.jwt.refresh.study.jwt.auth.domain.repository.AuthTokenRepository;
import com.example.jwt.refresh.study.jwt.boot.exception.RestException;
import com.example.jwt.refresh.study.jwt.boot.util.JwtUtils;
//import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsImpl;
//import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsServiceImpl;
import com.example.jwt.refresh.study.jwt.user.service.impl.principal.PrincipalDetailService;
import com.example.jwt.refresh.study.jwt.user.service.impl.principal.PrincipalDetails;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthJwtFilter extends OncePerRequestFilter {
    private final JwtUtils jwtUtils;
//    private final UserDetailsServiceImpl userDetailsService;

    private final PrincipalDetailService principalDetailService;
    private final AuthTokenRepository authTokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String accessToken = getAccessToken(request);
            String requestPath = request.getServletPath();

            log.info(requestPath);

            if(accessToken != null && jwtUtils.validateAccessToken(accessToken)) {
                log.info(accessToken);
                // 만일, DB 내에 존재하는 Access Token 과 전달받은 Access Token 이 다를 경우 예외를 발생시킨다.
                if(!authTokenRepository.existsByAccessToken(accessToken)) {
                    throw new RestException(HttpStatus.BAD_REQUEST, "Access Token 이 DB 내 토큰과 일치하지 않습니다. 이전 사용자/로그아웃된 사용자, 혹은 조작된 토큰일 수 있습니다.");
                }

                // Security Context 에 인증한다.
                String username = jwtUtils.getUserNameFromAccessToken(accessToken);
                log.info("username = {}", username);
                PrincipalDetails principalDetails = (PrincipalDetails) principalDetailService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch ( StackOverflowError e ) {

            System.err.println("Exception: " + e );
            // Here is the important thing to do
            // when catching StackOverflowError's:
            e.printStackTrace();
            // do some cleanup and destroy the thread or unravel if possible.
        }
        catch (SecurityException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }
    }

    public String getAccessToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.replace("Bearer ", "");
        }

        return null;
    }
}
