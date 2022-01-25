package com.example.utubeclone.core;

import com.example.utubeclone.auth.exception.EmailAlreadyExistsException;
import com.example.utubeclone.auth.exception.UsernameAlreadyExistException;
import com.example.utubeclone.core.dto.MessageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class ApiControllerAdvice {
    @ExceptionHandler(value={UsernameAlreadyExistException.class, EmailAlreadyExistsException.class})
    public ResponseEntity<MessageResponse> handleUsernameAlreadyExistException(UsernameAlreadyExistException ex, HttpServletRequest request) {
        MessageResponse messageResponse = new MessageResponse(
                ex.getMessage(), HttpStatus.BAD_REQUEST.value()
        );
        return new ResponseEntity<>(
                messageResponse, HttpStatus.BAD_REQUEST
        );
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<MessageResponse> handleAuthenticationException(AuthenticationException e) {
        return new ResponseEntity<>(
                new MessageResponse(
                        e.getMessage(),
                        HttpStatus.UNAUTHORIZED.value()
                ),
                HttpStatus.UNAUTHORIZED
        );
    }


    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<MessageResponse> handleValidException(MethodArgumentNotValidException ex, HttpServletRequest request) {
        FieldError fieldOnError = ex.getBindingResult().getFieldError();
        String message = fieldOnError != null ? fieldOnError.getDefaultMessage() : ex.getMessage();
        MessageResponse messageResponse = new MessageResponse(
                message, HttpStatus.BAD_REQUEST.value()
        );
        return new ResponseEntity<>(messageResponse, HttpStatus.BAD_REQUEST);
    }

}
