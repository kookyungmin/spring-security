package net.happykoo.security.authentication;

import net.happykoo.security.principal.User;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

//통행증 발급
public class UserAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    private Map<String, User> userDB = new HashMap<>();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserAuthenticationToken token = (UserAuthenticationToken) authentication;

        //인증 로직
        if (userDB.containsKey(token.getCredentials())) {
            User user = userDB.get(token.getCredentials());

            return UserAuthenticationToken.builder()
                    .principal(user)
                    .details(user.getName()) //추가 정보
                    .authenticated(true)
                    .build();
        }

        //처리할 수 없는 것은 null로 반환
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UserAuthenticationToken.class;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Set.of(
                new User("koo", "구경민", Set.of(new SimpleGrantedAuthority("ROLE_USER"))),
                new User("koo2", "구경민2", Set.of(new SimpleGrantedAuthority("ROLE_USER")))
        ).forEach(u -> userDB.put(u.getId(), u));
    }
}
