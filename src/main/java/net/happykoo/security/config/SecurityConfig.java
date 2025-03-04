package net.happykoo.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.happykoo.security.domain.User;
import net.happykoo.security.filter.JWTAuthenticationFilter;
import net.happykoo.security.filter.JWTCheckFilter;
import net.happykoo.security.service.CustomOAuth2SuccessHandler;
import net.happykoo.security.service.CustomRememberMeService;
import net.happykoo.security.service.UserService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpSessionEvent;
import javax.sql.DataSource;
import java.util.List;

@Configuration
@EnableWebSecurity(debug = true)
//prePost로 권한 설정 작동
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    private final UserService userService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           JWTCheckFilter jwtCheckFilter,
                                           JWTAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http.csrf()
                .disable()
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) //로그인
                .addFilterAt(jwtCheckFilter, BasicAuthenticationFilter.class) //token 검증
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization.baseUri("/test/oauth2/authorization"))
                        .redirectionEndpoint(redirection -> redirection.baseUri("/test/oauth2/callback/*"))
                        .successHandler(customOAuth2SuccessHandler()))
                .exceptionHandling()
                .authenticationEntryPoint(((request, response, authException) -> { response.getWriter().write("FAILED");}));

        return http.build();
    }

    private AuthenticationSuccessHandler customOAuth2SuccessHandler() {
        return new CustomOAuth2SuccessHandler();
    }

    @Bean
    public JWTCheckFilter jwtCheckFilter(AuthenticationManager authenticationManager,
                                         UserService userService) {
        return new JWTCheckFilter(authenticationManager, userService);
    }

    @Bean
    public JWTAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        return new JWTAuthenticationFilter(authenticationManager);
    }

    //role hierarchy 설정
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER"); //admin 은 user 가 사용하는 것을 모두 사용할 수 있음

        return roleHierarchy;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        //web resource 인증 통과
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations(), PathRequest.toH2Console());
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userService)
                .and()
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher() {
            @Override
            public void sessionCreated(HttpSessionEvent event) {
                super.sessionCreated(event);
                log.info("####### session created! {}", event.getSession().getId());
            }

            @Override
            public void sessionDestroyed(HttpSessionEvent event) {
                super.sessionDestroyed(event);
                log.info("####### session destroyed! {}", event.getSession().getId());
            }

            @Override
            public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
                super.sessionIdChanged(event, oldSessionId);
                log.info("####### session changed! {} > {}", oldSessionId, event.getSession().getId());
            }
        });
    }

    @Bean
    public RememberMeServices rememberMeServices(PersistentTokenRepository tokenRepository) {
        return new CustomRememberMeService("uniqueAndSecretKey", userService, tokenRepository);
    }

    @Bean
    public PersistentTokenRepository tokenRepository(DataSource dataSource) {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();

        jdbcTokenRepository.setDataSource(dataSource);
        try {
            jdbcTokenRepository.removeUserTokens("test");
        } catch (Exception e) {
            jdbcTokenRepository.setCreateTableOnStartup(true);
        }
        return jdbcTokenRepository;
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
        return new CompositeSessionAuthenticationStrategy(
                List.of(
                        new RegisterSessionAuthenticationStrategy(sessionRegistry),
                        new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry)
                )
        );
    }


    @PostConstruct
    public void initializeDb() {
        if (!userService.findUserByEmail("rudals4549").isPresent()) {
            User user = userService.save(User.builder()
                    .email("rudals4549")
                    .enabled(true)
                    .password("1234")
                    .build());
            userService.addAuthority(user.getUserId(), "ROLE_USER");
        }
    }
}
