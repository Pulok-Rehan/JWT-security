package jwtspringsecurity.JWT.security.service;

import jwtspringsecurity.JWT.security.dto.SignupRequest;
import jwtspringsecurity.JWT.security.model.User;

public interface AuthenticationService {
    User signup(SignupRequest signupRequest);
}
