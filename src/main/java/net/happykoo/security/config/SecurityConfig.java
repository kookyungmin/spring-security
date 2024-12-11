package net.happykoo.security.config;

import lombok.RequiredArgsConstructor;
import net.happykoo.security.authentication.UserAuthenticationProvider;
import net.happykoo.security.filter.CustomUsernamePasswordAuthenticationFilter;
import net.happykoo.security.service.UserService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;
import java.nio.file.Path;

@Configuration
@EnableWebSecurity(debug = true)
//prePost로 권한 설정 작동
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserService userService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           AuthenticationManager authenticationManager) throws Exception {
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
        .addFilterBefore(new CustomUsernamePasswordAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
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

    //Inmemory
//    @Bean
//    public InMemoryUserDetailsManager userDetailsManager() {
//        UserDetails user = User.builder()
//                .username("user1")
//                .password(passwordEncoder().encode("1111"))
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("user2")
//                .password(passwordEncoder().encode("1111"))
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }

//    @Bean
//    public AuthenticationProvider authenticationProvider() {
//        return new UserAuthenticationProvider();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(HttpSecurity http,
//                                                       AuthenticationProvider authenticationProvider) throws Exception {
//        return http.getSharedObject(AuthenticationManagerBuilder.class)
//                .authenticationProvider(authenticationProvider)
//                .build();
//    }
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userService)
                .and()
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }
}
