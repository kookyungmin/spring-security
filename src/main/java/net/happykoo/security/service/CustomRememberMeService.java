package net.happykoo.security.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

public class CustomRememberMeService extends PersistentTokenBasedRememberMeServices {

    public CustomRememberMeService(String key,
                                   UserDetailsService userDetailsService,
                                   PersistentTokenRepository tokenRepository) {
        super(key, userDetailsService, tokenRepository);
        setParameter("rememberMe");
    }

    @Override
    protected boolean rememberMeRequested(HttpServletRequest request, String parameter) {
        Object rememberMe = request.getAttribute("rememberMe");
        return rememberMe != null && Boolean.TRUE.equals(rememberMe);
    }
}
