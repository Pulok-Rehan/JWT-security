package jwtspringsecurity.JWT.security.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {
    public String extractUsername(String token);
    public Boolean checkTokenValidity(String token, UserDetails userDetails);
}
