package jwtspringsecurity.JWT.security.serviceImpl;

import jwtspringsecurity.JWT.security.dto.SignupRequest;
import jwtspringsecurity.JWT.security.enums.Role;
import jwtspringsecurity.JWT.security.model.User;
import jwtspringsecurity.JWT.security.repository.UserRepository;
import jwtspringsecurity.JWT.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
@RequiredArgsConstructor
@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User signup(SignupRequest signupRequest){
        User user = User.builder()
                .firstName(signupRequest.getFirstName())
                .lastName(signupRequest.getLastName())
                .email(signupRequest.getEmail())
                .password(passwordEncoder.encode(signupRequest.getPassword()))
                .role(Role.USER).build();
        return userRepository.save(user);
    }
}
