package com.hart.mfa.controller;

import com.hart.mfa.dto.UserDto;
import com.hart.mfa.exception.CustomException;
import com.hart.mfa.mailSender.MailService;
import com.hart.mfa.model.User;
import com.hart.mfa.request.LoginRequest;
import com.hart.mfa.response.ApiResponse;
import com.hart.mfa.security.jwt.JwtUtil;
import com.hart.mfa.service.user.IUserService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static org.springframework.http.HttpStatus.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final IUserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final MailService mailService;

    @Value("${auth.token.jwtSecret}")
    private String SECRET_KEY;

    String accessToken = "";


    @PostMapping("/register")
    public ResponseEntity<ApiResponse> registerUser(@RequestBody User request){
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

            // Generate six digits OTP
            Random random = new Random();
            int otp = 100000 + random.nextInt(900000);

            // Generate JWT token
            String jwt = jwtUtil.generateToke(user.getEmail(), otp);
            accessToken = jwt;

            // Email Template
            String subject = "Your OTP for Verification";
            String content = """
                <p>Dear %s,</p>
                <p>Your One-Time Password for verification is:</p>
                <h2 style="color: #2e6c80;">%d</h2>
            """;
            String formattedContent = String.format(content, user.getFirstName(), otp);

            try {
                // Send OTP
                mailService.sendMail(user.getEmail(), subject, formattedContent);

                return ResponseEntity.ok(
                        new ApiResponse(true, "Login successful. A verification code has been sent to your email.", null)
                );
            } catch (MessagingException | UnsupportedEncodingException e) {
                // Log email errors, but don't fail login
                return ResponseEntity.status(EXPECTATION_FAILED).body(
                        new ApiResponse(false, "Failed to send email: " + e.getMessage(), null)
                );
            }
        } catch (CustomException e) {
            return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(false, e.getMessage(), null));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(false, "Invalid Email or Password", null));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ApiResponse(false, "An error occurred during login: " + e.getMessage(), null));
        }
    }


    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse> verifyOTP(@RequestParam(required = false) String otp) {
        try {
            // Check if OTP or access token is missing
            // Check if user has loggedIn
            // Extract OTP code sent to the user from jwt object
            // Compare the provided OTP with the extracted OTP

            if (otp == null || otp.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                        new ApiResponse(false, "OTP is missing", null));
            }

            if (accessToken == null || accessToken.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                        new ApiResponse(false, "No authenticated user, please login and try again.", null));
            }

            Object jwtObject = Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(accessToken).getBody();

            if (otp.equals(String.valueOf(((io.jsonwebtoken.Claims) jwtObject).get("otp")))) {
                Map<String, Object> data = new HashMap<>();
                try {
                    User user = userService.findByEmail(((Claims) jwtObject).getSubject()); // Fetch user record
                    UserDto userDto = userService.convertToDto(user);
                    data.put("user", userDto);
                    data.put("access_token", accessToken);

                    return ResponseEntity.ok(new ApiResponse(true, "Verification successful", data));
                }catch (CustomException e) {
                    return ResponseEntity.status(NOT_FOUND).body(new ApiResponse(false, e.getMessage(), null));
                }
            }else {
                return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(new ApiResponse(false, "Invalid OTP", null));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ApiResponse(false, "An unexpected error occurred: " + e.getMessage(), null));
        }
    }
}

