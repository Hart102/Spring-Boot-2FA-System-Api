package com.hart.mfa.controller;

import com.hart.mfa.dto.UserDto;
import com.hart.mfa.model.User;
import com.hart.mfa.response.ApiResponse;
import com.hart.mfa.service.user.IUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
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

    /**
     * Fetches the profile of the currently authenticated user.
     * @return ResponseEntity containing user profile information or error details.
     */
   @Operation(
        summary = "Get User Profile",
        description = "Fetch the profile of the current authenticated user.",
        security = @SecurityRequirement(name = "bearer-key")
   )

    @GetMapping("/user/profile")
    public ResponseEntity<ApiResponse> getProfile() {
        // Get Jwt auth Object
        // Check if user is authenticated
        // If No return an Unauthorized message
        // If yes find and return user using the email
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

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
