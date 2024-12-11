package net.happykoo.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.happykoo.security.authentication.UserAuthenticationToken;
import net.happykoo.security.dto.LoginDto;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

public class CustomUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    public CustomUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        setFilterProcessesUrl("/login");
        setAuthenticationSuccessHandler(((request, response, authentication) -> {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);

            response.getWriter().write("ok");
        }));
        setAuthenticationFailureHandler(((request, response, exception) -> {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            response.getWriter().write("failed");
        }));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        //여기서 Token 을 여러 개로 분기 할수도 있음
        ObjectMapper mapper = new ObjectMapper();

        try (InputStream inputStream = request.getInputStream()) {
            LoginDto loginDto = mapper.readValue(inputStream, LoginDto.class);
            UserAuthenticationToken token = UserAuthenticationToken.builder()
                    .credentials(loginDto.getId())
                    .build();

            return this.getAuthenticationManager().authenticate(token);
        } catch (IOException e) {
            throw new RuntimeException("Content Type is not application/json");
        }
    }
}