package net.happykoo.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.happykoo.security.domain.User;
import net.happykoo.security.filter.CustomUsernamePasswordAuthenticationFilter;
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
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSessionEvent;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity(debug = true)
//prePost로 권한 설정 작동
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    private final UserService userService;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           AuthenticationManager authenticationManager,
                                           RememberMeServices rememberMeServices) throws Exception {
        //UsernameAndPasswordAuthenticationFilter 는 csrf token 필수!
        http.authorizeRequests((requests) -> {
           requests.antMatchers("/login").permitAll()
                   .anyRequest().authenticated();
        })
        .formLogin().disable() //spring 이 기본적으로 제공하는 HTML나 MVC 패턴의 resource 이용
        .httpBasic().disable()
        .csrf().ignoringAntMatchers("/login", "/logout")
                .and()
//        .csrf().disable()
        .addFilterBefore(new CustomUsernamePasswordAuthenticationFilter(authenticationManager, rememberMeServices),
                UsernamePasswordAuthenticationFilter.class)
        .exceptionHandling()
        .accessDeniedHandler((request, response, accessDeniedException) -> {
           response.setContentType("application/json");
           response.setStatus(HttpServletResponse.SC_FORBIDDEN);
           response.getWriter().write("{\"error\": \"ForBidden\"}");
        })
        .authenticationEntryPoint(((request, response, authException) -> {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"UnAuthorized\"}");
        }))
        .and()
        .rememberMe(rememberMe -> rememberMe
                .rememberMeServices(rememberMeServices)
        )
        .logout()
        .logoutUrl("/logout") // 로그아웃 엔드포인트
        .logoutSuccessHandler((request, response, authentication) -> {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("{\"message\": \"Logout successful\"}");
        })
        .invalidateHttpSession(true)
        .deleteCookies("JSESSIONID");

        return http.build();
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
