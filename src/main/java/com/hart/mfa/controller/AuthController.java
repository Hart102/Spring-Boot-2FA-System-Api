package com.hart.mfa.controller;

import com.hart.mfa.dto.UserDto;
import com.hart.mfa.mailSender.MailService;
import com.hart.mfa.model.User;
import com.hart.mfa.request.LoginRequest;
import com.hart.mfa.response.ApiResponse;
import com.hart.mfa.security.jwt.JwtUtil;
import com.hart.mfa.service.user.IUserService;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final IUserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    private final MailService mailService;


    @PostMapping("/register")
    public ResponseEntity<ApiResponse> createUser(@RequestBody User request){
        try {
            User user = userService.createUser(request);
            UserDto userDto = userService.convertToDto(user);
            return ResponseEntity.ok(new ApiResponse(true, "Registration successful", userDto));
        } catch (Exception e) {
            return ResponseEntity.status(CONFLICT).body(new ApiResponse(false, e.getMessage(), null));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse> login(@RequestBody LoginRequest request) {
        try {
            // Authenticate user
            User user = userService.findByEmail(request.getEmail());
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            // Generate JWT token
            String jwt = jwtUtil.generateToke(user.getEmail());

            // Send verification email
            String subject = "Hello from Spring Boot";
            String content = "<p>Hello,</p><p>This is a test email sent from Spring Boot.</p>";

            try {
                mailService.sendMail(user.getEmail(), subject, content);

                Map<String, Object> token = new HashMap<>();
                token.put("token", jwt);

                return ResponseEntity.ok(
                        new ApiResponse(true, "Login successful. A verification code has been sent to you", token)
                );
            } catch (MessagingException | UnsupportedEncodingException e) {
                // Log email errors, but don't fail login
                return ResponseEntity.status(EXPECTATION_FAILED).body(
                        new ApiResponse(false, "Failed to send email: " + e.getMessage(), null)
                );
            }


        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(false, "Invalid Email or Password", null)
            );
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ApiResponse(false, "An error occurred during login: " + e.getMessage(), null)
            );
        }
    }

}

