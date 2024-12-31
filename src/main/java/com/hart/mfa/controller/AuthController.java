package com.hart.mfa.controller;

import com.hart.mfa.dto.UserDto;
import com.hart.mfa.exception.CustomException;
import com.hart.mfa.model.User;
import com.hart.mfa.request.LoginRequest;
import com.hart.mfa.response.ApiResponse;
import com.hart.mfa.security.jwt.JwtUtil;
import com.hart.mfa.service.user.IUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final IUserService userService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;


    @PostMapping("/register")
    public ResponseEntity<ApiResponse> createUser(@RequestBody User request){
        try {
            User user = userService.createUser(request);
            UserDto userDto = userService.convertToDto(user);
            return ResponseEntity.ok(new ApiResponse(true, "Registration success", userDto));
        } catch (Exception e) {
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(false, e.getMessage(), null));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse> login(@RequestBody LoginRequest request) {
        try {
            User user = userService.findByEmail(request.getEmail());

            authenticationManager.authenticate(
                  new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
            String jwt = jwtUtil.generateToke(user.getEmail());

            Map<String, Object> token = new HashMap<>();
            token.put("token", jwt);
            return ResponseEntity.ok(new ApiResponse(true, "Login successful", token));
        } catch (CustomException e) {
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(false, e.getMessage(), null));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiResponse(false, "Invalid Email or Password", null));
        }

    }
}

