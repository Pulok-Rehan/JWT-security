package jwtspringsecurity.JWT.security.controller;

import jwtspringsecurity.JWT.security.dto.SignupRequest;
import jwtspringsecurity.JWT.security.model.User;
import jwtspringsecurity.JWT.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RequiredArgsConstructor

@RestController
@RequestMapping(path = "app/v1")
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping(path = "/user")
    public ResponseEntity<User> signup(@RequestBody SignupRequest signupRequest){
        return ResponseEntity.ok(authenticationService.signup(signupRequest));
    }
}
