package net.happykoo.security.voter;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

import java.util.Collection;
import java.util.Objects;

public class CustomVoter implements AccessDecisionVoter<MethodInvocation> {
    private static String PREFIX = "TEST_";
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute.getAttribute().startsWith(PREFIX);
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return MethodInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, MethodInvocation object, Collection<ConfigAttribute> attributes) {
        String role = attributes.stream()
                .filter(attr -> Objects.nonNull(attr.getAttribute()) && attr.getAttribute().startsWith(PREFIX))
                .map(attr -> attr.getAttribute().substring(PREFIX.length()))
                .findFirst()
                .orElse(null);

        if (Objects.nonNull(role) && authentication.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_" + role))) {
            return ACCESS_GRANTED;
        }

        return ACCESS_DENIED;
    }
}
