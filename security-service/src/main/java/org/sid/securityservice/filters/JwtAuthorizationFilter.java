package org.sid.securityservice.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.sid.securityservice.JwtUtil;
import org.sid.securityservice.SecurityConfig;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        if(httpServletRequest.getServletPath().equals("/refreshToken")||httpServletRequest.getServletPath().equals("/login")){
              filterChain.doFilter(httpServletRequest,httpServletResponse);
        }
        else {
            String authHeader = httpServletRequest.getHeader(JwtUtil.AUTH_HEADER);
            if (authHeader != null && authHeader.startsWith(JwtUtil.HEADER_PREFIX)) {
                try {
                    String jwt = authHeader.substring(JwtUtil.HEADER_PREFIX.length());
                    Algorithm hmac256 = Algorithm.HMAC256(JwtUtil.SECRET);
                    JWTVerifier jwtVerifier = JWT.require(hmac256).build();
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    String username = decodedJWT.getSubject();
                    List<String> roles = decodedJWT.getClaim(JwtUtil.ROLES_CLAIM_NAME).asList(String.class);
                    UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(username, null, roles.stream().map(r -> new SimpleGrantedAuthority(r)).collect(Collectors.toList()));

                    SecurityContextHolder.getContext().setAuthentication(user);
                    filterChain.doFilter(httpServletRequest, httpServletResponse);
                } catch (Exception e) {
                    throw new RuntimeException(e.getMessage());
                }
            }
            else {
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }
        }
    }
}
