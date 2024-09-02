package com.example.jwtproject.config;

import com.example.jwtproject.jwt.JWTFilter;
import com.example.jwtproject.jwt.JWTUtil;
import com.example.jwtproject.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity //Security를 위한 Config
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //cors 설정
        //loginFilter에서 cors문제를 해결하게 된다.
        http
                .cors(corsCustomizer->corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;

                    }
                }));

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

                        //reissue 경로 모든 권한 허용
                        .requestMatchers("/reissue").permitAll()

                        //나머지는 로그인한 사용자만 허용
                        .anyRequest().authenticated());

        //LoginFilter 앞에 JWTFilter를 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        
        //기존 filter가 있던 자리에 custom한 LoginFilter 등록
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //세션 설정
        //jwt의 session은 stateless 상태로 관리한다.
        http
                .sessionManagement((session)-> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
