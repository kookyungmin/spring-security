package net.happykoo.security.domain;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "sp_user_authority")
@IdClass(Authority.class)
public class Authority implements GrantedAuthority {
    @Id
    @Column(name = "user_id")
    private Long userId;
    @Id
    private String authority;
}
