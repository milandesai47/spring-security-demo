package com.security.milan.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfiguration jwtConfiguration;

    public JwtTokenVerifier( JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = httpServletRequest.getHeader(jwtConfiguration.getAuthorizationHeader());

        if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfiguration.getTokenPrefix())){
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }
        String token = authorizationHeader.replace(jwtConfiguration.getTokenPrefix() , "");

        try{
            JwtParser claimedJws = Jwts.parserBuilder()
                    .setSigningKey(jwtConfiguration.secretkey())
                    .build();

            Claims body = claimedJws.parseClaimsJws(token).getBody();
            String username = body.getSubject();
            List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities");

            Set<SimpleGrantedAuthority> authority = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    authority
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }catch (JwtException e){
            throw new IllegalStateException(String.format("Token not trusted %s " , token));
        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }
}
