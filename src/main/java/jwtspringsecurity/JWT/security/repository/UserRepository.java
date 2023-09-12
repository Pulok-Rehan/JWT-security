package jwtspringsecurity.JWT.security.repository;

import jwtspringsecurity.JWT.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}
