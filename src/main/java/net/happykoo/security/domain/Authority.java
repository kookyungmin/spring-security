package net.happykoo.security.domain;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "sp_user_authority")
public class Authority implements GrantedAuthority {
    @Id
    @Column(name = "user_id")
    private Long userId;
    @Id
    private String authority;
}
