package com.example.jwt.refresh.study.jwt.boot.config;

import com.example.jwt.refresh.study.jwt.auth.filter.AuthJwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {
    private final AuthJwtFilter authJwtFilter;
    private final CorsConfig corsConfig;
    private static final String[] PERMIT_URL_ARRAY = {
            /* swagger v2 */
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**",
            /* swagger v3 */
            "/v3/api-docs/**",
            "/swagger-ui/**"
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManagerBean(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> web.ignoring().antMatchers("/resources/**"));
    }

    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http

                .oauth2Login()
                .and()
                // CORS
                .cors().configurationSource(corsConfig.corsFilter())
                .and()
                // CSRF 해제 - JWT 사용하기때문
                .csrf().disable()
                // JWT 사용을 위한 Stateless Policy 설정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeHttpRequests((authz) -> authz
                        .antMatchers(PERMIT_URL_ARRAY).permitAll()
                        .antMatchers(HttpMethod.OPTIONS).permitAll()
                        .antMatchers("/member/**").permitAll()
                        .antMatchers("/file/**").permitAll()
                        .antMatchers("/auth/**").permitAll()
                        .antMatchers("/**/adm/**").hasAnyRole("ADMIN")
                        .anyRequest().authenticated()
                        .and()
                        .addFilterBefore(authJwtFilter, UsernamePasswordAuthenticationFilter.class)
                );
//        http.authenticationManager(http.getSharedObject(AuthenticationConfiguration.class).getAuthenticationManager());

        return http.build();
    }

}
