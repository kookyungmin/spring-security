package net.happykoo.security.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginDto {
    private String id;
    private String password;
    private boolean rememberMe;
}
