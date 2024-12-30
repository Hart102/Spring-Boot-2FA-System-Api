package com.hart.mfa.controller;

import com.hart.mfa.response.ApiResponse;
import com.hart.mfa.service.user.IUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
public class UserController {

    private final IUserService userService;

    public ResponseEntity<ApiResponse> getUserById(@PathVariable Long userId) {
        return null;
    }
}
