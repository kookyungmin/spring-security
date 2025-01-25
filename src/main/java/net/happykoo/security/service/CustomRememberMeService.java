package net.happykoo.security.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

public class CustomRememberMeService extends TokenBasedRememberMeServices {

    public CustomRememberMeService(String key, UserDetailsService userDetailsService) {
        super(key, userDetailsService);
        setParameter("rememberMe");
    }

    @Override
    protected boolean rememberMeRequested(HttpServletRequest request, String parameter) {
        Object rememberMe = request.getAttribute("rememberMe");
        return rememberMe != null && Boolean.TRUE.equals(rememberMe);
    }
}
