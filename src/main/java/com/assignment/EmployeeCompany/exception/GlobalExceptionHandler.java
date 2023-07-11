package com.assignment.EmployeeCompany.exception;

import com.assignment.EmployeeCompany.entity.ResponseMessage;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private ResponseEntity<ResponseMessage> createErrorResponse(String errorMessage) {
        logger.error(errorMessage);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseMessage(Boolean.FALSE, errorMessage));
    }

    @ExceptionHandler(EmployeeNotFoundException.class)
    public ResponseEntity<ResponseMessage> empNotFoundException(EmployeeNotFoundException exception, WebRequest req) {
        ResponseMessage msg = new ResponseMessage(Boolean.FALSE, exception.getMessage());
        logger.error(exception.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(msg);
    }

    @ExceptionHandler(CompanyNotFoundException.class)
    public ResponseEntity<ResponseMessage> compNotFoundException(CompanyNotFoundException exception, WebRequest req) {
        ResponseMessage msg = new ResponseMessage(Boolean.FALSE, exception.getMessage());
        logger.error(exception.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(msg);
    }

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<ResponseMessage> customException(CustomException exception, WebRequest req) {
        ResponseMessage msg = new ResponseMessage(Boolean.FALSE, exception.getMessage());
        logger.error(exception.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(msg);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<ResponseMessage> nullPointerException (NullPointerException exception, WebRequest req) {
        ResponseMessage msg = new ResponseMessage(Boolean.FALSE, exception.getMessage());
        logger.error(exception.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(msg);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<ResponseMessage> methodArgumentNotValidException(MethodArgumentNotValidException exception) {
        Map<String, String> errorMap = new HashMap<>();
        ResponseMessage responseMessage = null;
        exception.getBindingResult().getFieldErrors().forEach(error -> {
            String field = error.getField();
            String message = error.getDefaultMessage();
            errorMap.put(field, message);
        });
        for (Map.Entry<String, String> entry : errorMap.entrySet()) {
            responseMessage = new ResponseMessage(Boolean.FALSE, entry.getValue());
            logger.error("Constraint Voilation : "+entry.getValue());
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMessage);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Object> handleInvalidArgument(ConstraintViolationException exception) {
        Map<String, String> errorMap = new HashMap<>();
        ResponseMessage responseMessage = null;
        exception.getConstraintViolations().forEach(violation -> {
            String field = violation.getPropertyPath().toString();
            String message = violation.getMessage();
            errorMap.put(field, message);
        });
        for (Map.Entry<String, String> entry : errorMap.entrySet()) {
            responseMessage = new ResponseMessage(Boolean.FALSE, entry.getValue());
            logger.error(entry.getValue());
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseMessage);
    }

    @ExceptionHandler(MismatchedInputException.class)
    public ResponseEntity<ResponseMessage> mismatchedInputException(MismatchedInputException exception, WebRequest req) {
        logger.error("Exception Exception : Employee data need to be passed properly");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseMessage(Boolean.FALSE, "Exception Exception : Employee data need to be passed properly"));
    }

    @ExceptionHandler(MissingServletRequestPartException.class)
    public ResponseEntity<ResponseMessage> handleMissingServletRequestPartException(MissingServletRequestPartException exception) {
        logger.error("Exception Occured : Image is not properly set");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseMessage(Boolean.FALSE, "Exception Occured : Image is not properly set"));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ResponseMessage> handleHttpMessageNotReadableException(HttpMessageNotReadableException exception) {
       logger.error("Exception Occured : Request body need to be passed properly");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseMessage(Boolean.FALSE, "Exception Occured : Request body need to be passed properly"));
    }

//    @ExceptionHandler(RuntimeException.class)
//    public ResponseEntity<ResponseMessage> runtimeExceptionException(RuntimeException exception) {
//        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseMessage(Boolean.FALSE, exception.getMessage()));
//    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseMessage> handleHttpMessageNotReadableException(Exception exception) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseMessage(Boolean.FALSE, exception.getMessage()));
    }


}