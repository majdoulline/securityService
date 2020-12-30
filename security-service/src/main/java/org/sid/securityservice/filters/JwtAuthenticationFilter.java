package org.sid.securityservice.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sid.securityservice.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException {
        System.out.println("attemptAuthentication");
        String username=httpServletRequest.getParameter("username");
        String password=httpServletRequest.getParameter("password");
        UsernamePasswordAuthenticationToken user=new UsernamePasswordAuthenticationToken(username,password);
        return authenticationManager.authenticate(user);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        User user=(User)authResult.getPrincipal();
        Algorithm hmac256=Algorithm.HMAC256(JwtUtil.SECRET);
        String jwtAccessToken=JWT.create()
                .withSubject(user.getUsername())
                .withIssuer(httpServletRequest.getRequestURL().toString())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.ACCESS_TOKEN_TIME_OUT))
                .withClaim(JwtUtil.ROLES_CLAIM_NAME,user.getAuthorities().stream().map(ga->ga.getAuthority()).collect(Collectors.toList()))
                .sign(hmac256);


        String jwtRefreshToken= JWT.create()
                .withSubject(user.getUsername())
                .withIssuer(httpServletRequest.getRequestURL().toString())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.REFRESH_TOKEN_TIME_OUT))
                .sign(hmac256);
        Map<String,String> idToken=new HashMap<>();
        idToken.put("access-token",jwtAccessToken);
        idToken.put("refresh-token",jwtRefreshToken);
        httpServletResponse.setContentType("application/json");
        new ObjectMapper().writeValue(httpServletResponse.getOutputStream(),idToken);
    }
}
