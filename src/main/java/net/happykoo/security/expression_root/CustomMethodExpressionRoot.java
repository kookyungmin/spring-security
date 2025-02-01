package net.happykoo.security.expression_root;

import lombok.Getter;
import lombok.Setter;
import net.happykoo.security.domain.User;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

@Getter
@Setter
public class CustomMethodExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {
    private MethodInvocation invocation;
    private Object filterObject;
    private Object returnObject;
    public CustomMethodExpressionRoot(Authentication authentication, MethodInvocation invocation) {
        super(authentication);
        this.invocation = invocation;
    }

    public boolean hasAuth(String name) {
        return ((User) getAuthentication().getPrincipal()).getUsername().equals(name);
    }

    @Override
    public Object getThis() {
        return this;
    }
}
