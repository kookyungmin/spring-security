package net.happykoo.security.dto;

import lombok.*;
import org.springframework.security.core.Authentication;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityMessage {
    private Authentication auth;
    private String message;
}
