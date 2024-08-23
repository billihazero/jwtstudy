package com.example.jwtproject.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //Security를 위한 Config
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable
        //session 방식에서는 session이 항상 고정되기 때문에 csrf 공격을 필수적으로 방어해야 하지만,
        //jwt방식은 session을 stateless상태로 관리하기 때문에 csrf 방어가 필수적이지 않다.
        http
                .csrf((auth) -> auth.disable());

        //Form 로그인 방식 disable
        //jwt방식으로 로그인을 진행하기 때문에
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가작업
        http
                .authorizeHttpRequests((auth)-> auth
                        //로그인, 루트, 조인 경로는 모든 권한을 허용
                        .requestMatchers("/login", "/", "/join").permitAll()

                        //admin 경로는 "ADMIN" 권한 가진자만 허용
                        .requestMatchers("/admin").hasRole("ADMIN")

                        //나머지는 로그인한 사용자만 허용
                        .anyRequest().authenticated());

        //세션 설정
        //jwt의 session은 stateless 상태로 관리한다.
        http
                .sessionManagement((session)-> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
