package com.example.jwt.refresh.study.jwt.auth.service.impl;

import com.example.jwt.refresh.study.jwt.auth.domain.model.AuthToken;
import com.example.jwt.refresh.study.jwt.auth.domain.model.Role;
import com.example.jwt.refresh.study.jwt.auth.domain.repository.AuthTokenRepository;
import com.example.jwt.refresh.study.jwt.auth.domain.repository.RoleRepository;
import com.example.jwt.refresh.study.jwt.auth.dto.request.AccessTokenRefreshRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignInRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignUpRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.response.AccessTokenRefreshResponseDto;
import com.example.jwt.refresh.study.jwt.auth.dto.response.KakaoLoginResponse;
import com.example.jwt.refresh.study.jwt.auth.dto.response.OauthTokenResponse;
import com.example.jwt.refresh.study.jwt.auth.dto.response.SignInResponseDto;
import com.example.jwt.refresh.study.jwt.auth.oauth.OAuth2UserInfo;
import com.example.jwt.refresh.study.jwt.auth.oauth.provider.GoogleUserInfo;
import com.example.jwt.refresh.study.jwt.auth.oauth.provider.KakaoUserInfo;
import com.example.jwt.refresh.study.jwt.auth.oauth.provider.NaverUserInfo;
import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import com.example.jwt.refresh.study.jwt.auth.service.AuthService;
import com.example.jwt.refresh.study.jwt.boot.exception.RestException;
import com.example.jwt.refresh.study.jwt.boot.util.JwtUtils;
import com.example.jwt.refresh.study.jwt.user.domain.model.Member;
import com.example.jwt.refresh.study.jwt.user.domain.model.User;
import com.example.jwt.refresh.study.jwt.user.domain.repository.MemberRepository;
import com.example.jwt.refresh.study.jwt.user.domain.repository.UserRepository;
//import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsImpl;
//import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsServiceImpl;
import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsImpl;
import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsServiceImpl;
import com.example.jwt.refresh.study.jwt.user.service.impl.principal.PrincipalDetailService;
import com.example.jwt.refresh.study.jwt.user.service.impl.principal.PrincipalDetails;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.json.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final MemberRepository memberRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final AuthTokenRepository authTokenRepository;
    private final InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository;
    private final UserDetailsServiceImpl userDetailsService;
    private final PrincipalDetailService principalDetailService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    /**
     * 로그인
     * @param signInRequestDto
     * @return
     * @throws Exception
     */
    @Override
    @Transactional
    public SignInResponseDto signIn(SignInRequestDto signInRequestDto) throws Exception {
        try {
            Authentication authentication = null;
            Boolean isNewUser = false;

            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    signInRequestDto.getUsername(),
                    signInRequestDto.getPassword()
            ));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.generateAccessToken(authentication);
            String refreshToken = jwtUtils.generateRefreshToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            Set<String> authorities = userDetails.getAuthorities().stream()
                    .map(role -> role.getAuthority())
                    .collect(Collectors.toSet());

            /**
             * RefreshToken을 한번 더 암호화 한 후, FakeRefreshToken을 사용자응답으로, 그리고 DB에 인덱스로 저장
             * 만일, DB 내에 해당 사용자가 이미 존재할 경우 기존값을 대체한다.
             */
            String fakeRefreshToken = passwordEncoder.encode(refreshToken);

            if(!authorities.contains("ROLE_ADMIN")) {
                Boolean isLogin = authTokenRepository.existsByUserSeq(userDetails.getSeq());
                if (isLogin) {
                    log.info("기본에 로그인된 일반 사용자입니다. DB값을 제거후 재삽입합니다.");
                    authTokenRepository.deleteByUserSeq(userDetails.getSeq());
                }
            } else {
                log.info("관리자는 중복 로그인 체크하지 않습니다.");
            }

            AuthToken authTokenEntity = AuthToken.builder()
                    .seq(fakeRefreshToken)
                    .userSeq(userDetails.getSeq())
                    .refreshToken(refreshToken)
                    .accessToken(accessToken)
                    .build();

            authTokenRepository.save(authTokenEntity);

            SignInResponseDto signInResponseDto = SignInResponseDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userSeq(userDetails.getSeq())
                    .username(userDetails.getUsername())
                    .type("Bearer")
                    .roles(authorities)
                    .build();

            return signInResponseDto;
        } catch (Exception e) {

            e.printStackTrace();
            log.info(e.getClass().getSimpleName());
            log.info(e.getMessage());
        }
        return null;
    }

    @Override
    @Transactional
    public Boolean signOut(String accessToken) throws Exception {
        PrincipalDetails userDetails = (PrincipalDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        accessToken = accessToken.replace("Bearer ", "");
        Integer deletedCnt = authTokenRepository.deleteByAccessToken(accessToken);
        log.info("AccessToken이 제거되었습니다.");

        SecurityContextHolder.clearContext();

        return true;
    }

    /**
     *
     * @param accessToken
     * @return
     * @throws Exception
     */
    @Transactional(readOnly = true)
    public String getUserName(String accessToken) throws Exception {
        PrincipalDetails userDetails = (PrincipalDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        return userDetails.getEmail();
    }

    /**
     * 회원가입 ( 유저 )
     * @param requestDto
     * @throws Exception
     *
     */
    @Override
    @Transactional
    public Boolean signUpCommon(SignUpRequestDto requestDto) throws Exception {
        User newUserEntity = null;
        Set<Role> roles = new HashSet<>();

        newUserEntity = User.builder()
                .username(requestDto.getUsername())
                .password(passwordEncoder.encode(requestDto.getPassword()))
                .name(requestDto.getName())
                .birth(requestDto.getBirth())
                .gender(requestDto.getGender())
                .email(requestDto.getEmail())
                .pushToken(requestDto.getPushToken())
                .build();

        Role trafficSafetyUserRole = roleRepository.findByRole(ERole.ROLE_TRAFFIC_SAFETY_USER)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당 Role을 찾지못했습니다."));
        roles.add(trafficSafetyUserRole);
        newUserEntity.setRoles(roles);

        User userEntity = userRepository.save(newUserEntity);

        return true;
    }

    /**
     *
     * @param requestDto
     * @return
     * @throws Exception
     */
    @Override
    @Transactional
    public Boolean signUpAdmin(SignUpRequestDto requestDto) throws Exception {
        if(userRepository.existsByUsername(requestDto.getUsername())){
            throw new RestException(HttpStatus.BAD_REQUEST, "이미 존재하는 계정입니다.");
        }

        User userEntity = User.builder()
                .username(requestDto.getUsername())
                .password(passwordEncoder.encode(requestDto.getPassword()))
                .name(requestDto.getName())
                .birth(requestDto.getBirth())
                .gender(requestDto.getGender())
                .email(requestDto.getEmail())
                .pushToken(requestDto.getPushToken())
                .build();

        Set<Role> roles = new HashSet<>();

        Role adminRole = roleRepository.findByRole(ERole.ROLE_ADMIN)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당하는 Role 을 찾지 못했습니다. role=" + ERole.ROLE_ADMIN));
        roles.add(adminRole);
        Role transUserRole = roleRepository.findByRole(ERole.ROLE_TRANS_USER)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당하는 Role 을 찾지 못했습니다. role=" + ERole.ROLE_TRANS_USER));
        roles.add(transUserRole);
        Role transManagerRole = roleRepository.findByRole(ERole.ROLE_TRANS_MANAGER)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당하는 Role 을 찾지 못했습니다. role=" + ERole.ROLE_TRANS_MANAGER));
        roles.add(transManagerRole);
        Role trafficSatefyUserRole = roleRepository.findByRole(ERole.ROLE_TRAFFIC_SAFETY_USER)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당하는 Role 을 찾지 못했습니다. role=" + ERole.ROLE_TRAFFIC_SAFETY_USER));
        roles.add(trafficSatefyUserRole);
        Role trafficSafetyManager = roleRepository.findByRole(ERole.ROLE_TRAFFIC_SAFETY_MANAGER)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당하는 Role 을 찾지 못했습니다. role=" + ERole.ROLE_TRAFFIC_SAFETY_MANAGER));
        roles.add(trafficSafetyManager);

        userEntity.setRoles(roles);
        userRepository.save(userEntity);

        return true;
    }

    /**
     * Refresh Token을 검사하여 새 AccessToken을 반환한다.
     * @param accessTokenRefreshRequestDto
     * @return
     */
    @Override
    @Transactional(noRollbackFor = RestException.class)
    public AccessTokenRefreshResponseDto accessTokenRefresh(AccessTokenRefreshRequestDto accessTokenRefreshRequestDto) {
        accessTokenRefreshRequestDto.setAccessToken(jwtUtils.getAccessTokenFromBearer(
                accessTokenRefreshRequestDto.getAccessToken()
        ));
        log.info(jwtUtils.validateRefreshToken(accessTokenRefreshRequestDto.getRefreshToken()).toString());
        String username = jwtUtils.getUserNameFromAccessToken(accessTokenRefreshRequestDto.getAccessToken());
        log.info(":::::"+username);

        if(!memberRepository.existsByEmail(username)) {
            throw new UsernameNotFoundException(username);
        }

        log.info(":::");
        if(!authTokenRepository.existsByAccessTokenAndSeq(accessTokenRefreshRequestDto.getAccessToken(),
                accessTokenRefreshRequestDto.getRefreshToken())) {
            log.error("Refresh Token 이 만료되었습니다. 해당 토근 정보를 DB에서 제거합니다.");
            authTokenRepository.deleteBySeq(accessTokenRefreshRequestDto.getRefreshToken());
            throw new RestException(HttpStatus.valueOf(401), "RefreshToken이 만료되었습니다. 해당 " +
                    "토큰 정보를 DB에서 제거합니다.");
        }
        log.info("::::");
        PrincipalDetails principalDetails = principalDetailService.loadUserByUsername(username);
        log.info(principalDetails.toString());
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                principalDetails, null, principalDetails.getAuthorities()
        );
        String newAccessToken = jwtUtils.generateAccessToken(authenticationToken);
        log.info(":::::");
        AuthToken authTokenEntity = authTokenRepository.findBySeq(accessTokenRefreshRequestDto.getRefreshToken())
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "찾을 수 없어"));

        authTokenEntity.updateAccessToken(newAccessToken);

        return AccessTokenRefreshResponseDto.builder()
                .accessToken(newAccessToken)
                .build();
    }

    /**
     *
     * @param code
     * @return
     */
    @Override
    @Transactional
    public KakaoLoginResponse oauthLogin(String code, String requestPath) {
        ClientRegistration provider = null;
        if(requestPath.contains("kakao")) {
            provider  = inMemoryClientRegistrationRepository.findByRegistrationId("kakao");
        } else if(requestPath.contains("google")) {
            provider  = inMemoryClientRegistrationRepository.findByRegistrationId("google");
        } else if(requestPath.contains("naver")) {
            provider = inMemoryClientRegistrationRepository.findByRegistrationId("naver");
        }

        log.info(provider.getClientSecret());
        OauthTokenResponse oauthTokenResponse = getToken(code, provider);
        log.info(oauthTokenResponse.getAccess_token() + "::::::Dfdfdf");
        Authentication authentication = null;

        if(requestPath.contains("kakao")) {
            authentication = getOAuthUserInfo("kakao", oauthTokenResponse, provider);
        } else if(requestPath.contains("google")) {
            authentication = getOAuthUserInfo("google", oauthTokenResponse, provider);
        } else if(requestPath.contains("naver")) {
            authentication = getOAuthUserInfo("naver", oauthTokenResponse, provider);
        }



        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        Set<String> authorities = principalDetails.getAuthorities()
                .stream().map(role -> role.getAuthority())
                .collect(Collectors.toSet());

        String accessToken = jwtUtils.generateAccessToken(authentication);
        String refreshToken = jwtUtils.generateRefreshToken(authentication);

        String fakeRefreshToken = passwordEncoder.encode(refreshToken);

        AuthToken authTokenEntity = AuthToken.builder()
                .seq(fakeRefreshToken)
                .userSeq(principalDetails.getMemberSeq())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        if(!authorities.contains("ROLE_ADMIN")) {
            Boolean isLogin = authTokenRepository.existsByUserSeq(principalDetails.getMemberSeq());
            if(isLogin) {
                log.info("기존에 로그인된 일반 사용자입니다. DB값을 추출후 재삽입합니다.");
                authTokenRepository.deleteByUserSeq(principalDetails.getMemberSeq());
            }
        } else {
            log.info("관리자는 중복 로그인 체크를 하지 않습니다.");
        }

        authTokenRepository.save(authTokenEntity);

        KakaoLoginResponse kakaoLoginResponse = KakaoLoginResponse.builder()
                .memeberSeq(principalDetails.getMemberSeq())
                .email(principalDetails.getEmail())
                .eRole(principalDetails.getERole())
                .accessToken(accessToken)
                .nickname(principalDetails.getNickname())
                .refreshToken(refreshToken)
                .build();

        return kakaoLoginResponse;
    }

    /**
     *
     * @param providerName
     * @param oauthTokenResponse
     * @param provider
     * @return
     */
    @Transactional
    private Authentication getOAuthUserInfo(String providerName, OauthTokenResponse oauthTokenResponse, ClientRegistration provider) {
        Map<String, Object> oauthrAttributes = getOAuthUserAttributes(provider, oauthTokenResponse);
        OAuth2UserInfo oAuth2UserInfo = null;

        if(providerName.equals("kakao")) {
            oAuth2UserInfo = new KakaoUserInfo(oauthrAttributes);
        } else if(providerName.equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oauthrAttributes);
        } else if(providerName.equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo(oauthrAttributes);
        }
        else {
            log.info("허용되지 않은 접근입니다.");
        }


        log.info("oauth.getEmail {}", oAuth2UserInfo.getEmail());
        log.info("oauth.getNickname {}", oAuth2UserInfo.getNickName());
        String provide = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String nickname = oAuth2UserInfo.getNickName();
        String email = oAuth2UserInfo.getEmail();
        String password = provide + providerId;

        Member member = memberRepository.findByEmail(email).orElse(null);

        if(member == null) {
            memberRepository.save(Member.builder()
                    .email(email)
                    .password(passwordEncoder.encode(password))
                    .nickname(nickname)
                    .eRole(ERole.ROLE_TRANS_USER)
                    .build());

        }

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(email, password);

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return authentication;
    }

    /**
     *
     * @param provider
     * @param oauthTokenResponse
     * @return
     */
    private Map<String, Object> getOAuthUserAttributes(ClientRegistration provider, OauthTokenResponse oauthTokenResponse) {
        OkHttpClient client = new OkHttpClient();
//        String param = "grant_type=authorization_code&client_id="+test.get("client_id")+"&redirect_uri="+test.get("redirect_uri")+"&client_secret="+test.get("client_secret")+"&code="+code;

        Request request = new Request.Builder()
                .url(provider.getProviderDetails().getUserInfoEndpoint().getUri())
                .addHeader("Authorization", "Bearer " + oauthTokenResponse.getAccess_token())
                .get()
                .build();

        try(Response response = client.newCall(request).execute()) {
            String responseResult = response.body().string();

            response.close();
            JSONObject responseFromJson = new JSONObject(responseResult);
            log.info(responseFromJson.toString());
            Map<String, Object> responseMap = new ObjectMapper().readValue(responseFromJson.toString(), Map.class);

            return responseMap;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RestException(HttpStatus.BAD_REQUEST, "");
        }
    }

    /**
     *
     * @param code
     * @param provider
     * @return
     */
    private OauthTokenResponse getToken(String code, ClientRegistration provider) {
        OkHttpClient client = new OkHttpClient();
        Map<String, String> test = tokenRequest(code,provider).toSingleValueMap();
        String param = "grant_type=authorization_code&client_id="+test.get("client_id")+"&redirect_uri="+test.get("redirect_uri")+"&client_secret="+test.get("client_secret")+"&code="+code;

        RequestBody requestBody = RequestBody.create(param, MediaType.parse("application/x-www-form-urlencoded;charset=utf-8"));

        Request request = new Request.Builder()
                .url(provider.getProviderDetails().getTokenUri())
                .post(requestBody)
                .build();

        try(Response response = client.newCall(request).execute()) {
            String responseResult = response.body().string();
            response.close();
            JSONObject responseFromJson = new JSONObject(responseResult);

            log.info(responseFromJson.toString());
            OauthTokenResponse oauthTokenResponse = new Gson().fromJson(responseFromJson.toString(), OauthTokenResponse.class);

            log.info(oauthTokenResponse.toString());
            return oauthTokenResponse;
        } catch (IOException e) {
            log.error(e.getMessage() + " 문제야 문제 온 세상속에");
            throw new RestException(HttpStatus.BAD_REQUEST, "");
        }
    }

    /**
     * 카카오 서버에 요청 정보를 담는다.
     * @param code
     * @param provider
     * @return
     */
    private MultiValueMap<String, String> tokenRequest(String code, ClientRegistration provider) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("code", code);
        formData.add("grant_type", "authorization_code");
        formData.add("redirect_uri", provider.getRedirectUri());
        formData.add("client_secret", provider.getClientSecret());
        formData.add("client_id", provider.getClientId());
        log.info(formData.get("grant_type").toString().getClass() +"나와라ㅏㅏㅏㅏㅏㅏㅏㅏ");
        return formData;
    }
}






















