package com.hart.mfa.security.user;

import com.hart.mfa.exception.CustomException;
import com.hart.mfa.model.User;
import com.hart.mfa.service.user.IUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailService implements UserDetailsService {
    private final IUserService userService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        try {
            User user = userService.findByEmail(email);

            // Map fetched user to UserDetails
            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getEmail())
                    .password(user.getPassword())
                    .build();
        } catch (CustomException e) {
            throw new UsernameNotFoundException(e.getMessage(), e);
        }
    }

}
