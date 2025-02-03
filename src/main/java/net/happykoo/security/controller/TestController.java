package net.happykoo.security.controller;

import net.happykoo.security.dto.SecurityMessage;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
    @RequestMapping("/")
    public String test() {
        return "test";
    }

    @RequestMapping("/auth")
    public Authentication auth() {
        return SecurityContextHolder.getContext()
                .getAuthentication();
    }

    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    @RequestMapping("/user")
    public SecurityMessage user() {
        return SecurityMessage.builder()
                .auth(SecurityContextHolder.getContext().getAuthentication())
                .message("User 정보")
                .build();
    }

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @RequestMapping("/admin")
    public SecurityMessage admin() {
        return SecurityMessage.builder()
                .auth(SecurityContextHolder.getContext().getAuthentication())
                .message("Admin 정보")
                .build();
    }

//    @PreAuthorize("hasAuth(#name)")
    @PreAuthorize("hasPermission(#name, 'user', 'read')")
    @RequestMapping("/greeting/{name}")
    public String hello(@PathVariable String name) {
        return "Hello " + name;
    }

//    @Secured("TEST_USER") //SecuredAnnotaionSecurityMetadataSource 이용 -> CustomMetadataSource 작성 가능
    @RequestMapping("/bye/{name}")
    public String bye(@PathVariable String name) {
        return "Bye" + name;
    }


}
