package com.hart.mfa.service.user;

import com.hart.mfa.exception.CustomException;
import com.hart.mfa.model.User;
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
            if(user == null || user.getEmail() == null){
                throw new UsernameNotFoundException("User not found!");
            }

            //Map fetched user to UserDetails
            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getEmail()).password(user.getPassword()).build();
        } catch (UsernameNotFoundException e) {
            throw new UsernameNotFoundException("User not found!");
        }
    }
}
