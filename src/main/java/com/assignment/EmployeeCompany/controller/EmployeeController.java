package com.assignment.EmployeeCompany.controller;

import com.assignment.EmployeeCompany.entity.ResponseMessage;
import com.assignment.EmployeeCompany.exception.CompanyNotFoundException;
import com.assignment.EmployeeCompany.exception.EmployeeNotFoundException;
import com.assignment.EmployeeCompany.entity.Employee;
import com.assignment.EmployeeCompany.service.EmployeeService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
public class EmployeeController {
    @Autowired
    private EmployeeService employeeService;

    private Logger logger = LoggerFactory.getLogger(EmployeeController.class);

    @PostMapping("/emp/comp/{compId}")
    public Employee saveEmployee(@Valid @PathVariable Long compId, @RequestParam("empData") String empData, @RequestParam("image") MultipartFile image) throws CompanyNotFoundException, IOException {
        logger.trace("Saving Employee.....");
        Employee employee =employeeService.saveEmployee(compId, empData, image);
        logger.trace("Employee Saved Successfully : {}",employee );
        return employee;
    }

    @GetMapping("/emp/comp/{compId}")
    public List<Employee> getEmployees(@Valid @PathVariable Long compId) throws EmployeeNotFoundException, CompanyNotFoundException {
        logger.trace("Fetching all employees.....");
        List<Employee> employeeList = employeeService.getEmployees(compId);
        logger.trace("Employees Fetched Successfully : {}", employeeList);
        return employeeList;
    }

    @GetMapping(value="/emp/{empId}/comp/{compId}")
    public Employee getEmployeeById(@Valid @PathVariable Long empId, @PathVariable Long compId) throws EmployeeNotFoundException, CompanyNotFoundException {
        logger.trace("Fetching employee with ID - {}.....", empId);
       Employee employee = employeeService.getEmployeeById(empId, compId);
        logger.trace("Employee Fetched Successfully : {}", employee);
        return employee;
    }

    @GetMapping(value="/empImg/{empId}/comp/{compId}")
    public ResponseEntity<byte[]> getEmployeeImageById(@Valid @PathVariable Long empId, @PathVariable Long compId) throws EmployeeNotFoundException, CompanyNotFoundException {
        logger.trace("Fetching employee image with ID - {}.....", empId);
        byte[] img = employeeService.getEmployeeImageById(empId, compId);
        logger.trace("Employee Image Fetched Successfully : {}", img);
        return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.valueOf("image/png")).body(img);
    }

    @PutMapping("/emp/comp/{compId}")
    public Employee updateEmployee(@Valid @PathVariable Long compId, @RequestParam String empData, @RequestParam MultipartFile image) throws CompanyNotFoundException, IOException, EmployeeNotFoundException {
        logger.trace("Updating Employee.....");
        Employee employee = employeeService.updateEmployee(compId, empData, image);
        logger.trace("Employee Updated Successfully : {}", employee);
        return employee;
    }

    @DeleteMapping("/emp/{empId}/comp/{compId}")
    public ResponseEntity<ResponseMessage> deleteEmployee(@Valid @PathVariable Long empId, @PathVariable Long compId) throws EmployeeNotFoundException, CompanyNotFoundException {
        logger.trace("Deleting employee with ID - {}.....", empId);
        employeeService.deleteEmployee(empId, compId);
        logger.trace("Employee Deleted Successfully");
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseMessage(Boolean.TRUE, "Employee with Id " + empId + " Deleted Successfully"));
    }
}