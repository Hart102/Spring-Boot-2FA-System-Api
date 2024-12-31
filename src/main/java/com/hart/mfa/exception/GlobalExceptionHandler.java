package com.hart.mfa.exception;

import com.hart.mfa.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.nio.file.AccessDeniedException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse> handleAccessDenied(AccessDeniedException ex) {
        ApiResponse response = new ApiResponse(false, "Access Denied. Please login and try again.", null);
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }
}
