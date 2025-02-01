package net.happykoo.security.config;

import net.happykoo.security.expression.CustomMethodExpressionRoot;
import net.happykoo.security.expression.CustomPermissionEvaluator;
import net.happykoo.security.voter.CustomVoter;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.ConsensusBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.List;

//FilterSecurityInterceptor, MethodSecurityInterceptor 별로 DecisionManager 가 다름
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {
    @Autowired
    private CustomPermissionEvaluator permissionEvaluator;
    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler() {
            @Override
            protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, MethodInvocation invocation) {
                CustomMethodExpressionRoot expressionRoot = new CustomMethodExpressionRoot(authentication, invocation);;
                expressionRoot.setPermissionEvaluator(getPermissionEvaluator());
                return expressionRoot;
            }
        };
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }

    @Override
    protected AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();

        ExpressionBasedPreInvocationAdvice expressionAdvice = new ExpressionBasedPreInvocationAdvice();
        expressionAdvice.setExpressionHandler(getExpressionHandler());

        decisionVoters.add(new PreInvocationAuthorizationAdviceVoter(expressionAdvice));
        decisionVoters.add(new RoleVoter());
        decisionVoters.add(new AuthenticatedVoter());
        decisionVoters.add(new CustomVoter());

//        return new AffirmativeBased(decisionVoters);
//        return new ConsensusBased(decisionVoters);
        ConsensusBased commitee = new ConsensusBased(decisionVoters);
        //deny, allow 가 동일하면 deny 하게 설정
        commitee.setAllowIfEqualGrantedDeniedDecisions(false);

        return commitee;
    }
}
