package net.happykoo.security.util;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import net.happykoo.security.domain.User;

import java.time.Instant;

@Slf4j
public class JwtUtil {
    private static SignatureAlgorithm algorithm = SignatureAlgorithm.HS512;
    private static String secretKey = "happykoo";
    private static final long ATK_EXPIRED_TIME = 20 * 60;
    private static final long RTK_EXPIRED_TIME = 60 * 60 * 24 * 7;

    public static String createAccessToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .signWith(algorithm, secretKey)
                .claim("exp", Instant.now().getEpochSecond() * ATK_EXPIRED_TIME)
                .compact();
    }

    public static String verify(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return null;
    }
}
