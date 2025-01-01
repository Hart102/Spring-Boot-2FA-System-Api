package com.hart.mfa.controller;

import com.hart.mfa.dto.UserDto;
import com.hart.mfa.model.User;
import com.hart.mfa.response.ApiResponse;
import com.hart.mfa.service.user.IUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
public class UserController {

    private final IUserService userService;

    @GetMapping("/user/profile")
    public ResponseEntity<ApiResponse> getProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || authentication.getPrincipal().equals("anonymousUser")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(false, "No authenticated user found. Please login and try again", null)
            );
        }

        try {
            String email = authentication.getName();
            User user = userService.findByEmail(email);
            UserDto userDto = userService.convertToDto(user);

            return ResponseEntity.ok(new ApiResponse(true, "User found", userDto));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ApiResponse(false, "Error fetching authenticated user", null)
            );
        }
    }

}
