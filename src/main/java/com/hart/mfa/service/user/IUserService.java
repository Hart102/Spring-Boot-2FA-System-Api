package com.hart.mfa.service.user;

import com.hart.mfa.dto.UserDto;
import com.hart.mfa.model.User;
import org.springframework.security.core.userdetails.UserDetails;

public interface IUserService {
    User createUser(User user);
    User getUserById(Long userId);
    User findByEmail(String email);
    UserDto convertToDto(User user);
}
