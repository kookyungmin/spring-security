package net.happykoo.security.authentication;

import lombok.*;
import net.happykoo.security.principal.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;

//사용자가 발급받을 통행증
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserAuthenticationToken implements Authentication {
    private User principal; //output(사용자 정보)
    private String credentials; //input (인증 정보)
    private String details;
    private boolean authenticated;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Objects.isNull(principal) ? new HashSet<>() : principal.getRole();
    }

    @Override
    public String getName() {
        return Objects.isNull(principal) ? null : principal.getName();
    }
}
