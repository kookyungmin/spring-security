package net.happykoo.security.service;

import lombok.RequiredArgsConstructor;
import net.happykoo.security.domain.Authority;
import net.happykoo.security.domain.User;
import net.happykoo.security.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findUserByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    public Optional<User> findUserByEmail(String email) {
        return userRepository.findUserByEmail(email);
    }

    public void addAuthority(Long userId, String role) {
        userRepository.findById(userId).ifPresent(user -> {
            Authority newRole = new Authority(user.getUserId(), role);
            Set<Authority> authorities = new HashSet<>();
            if (user.getAuthorities() != null) {
                authorities.addAll(user.getAuthorities());
            }
            authorities.add(newRole);
            user.setAuthorities(authorities);
            save(user);
        });
    }
}
