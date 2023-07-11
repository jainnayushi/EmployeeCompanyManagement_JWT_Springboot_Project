package com.assignment.EmployeeCompany.controller;

import com.assignment.EmployeeCompany.entity.ResponseMessage;
import com.assignment.EmployeeCompany.entity.Company;
import com.assignment.EmployeeCompany.exception.CompanyNotFoundException;
import com.assignment.EmployeeCompany.service.CompanyService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
public class CompanyController {
    @Autowired
    private CompanyService companyService;

    private Logger logger = LoggerFactory.getLogger(CompanyController.class);

    @PostMapping("/comp")
    public Company saveCompany(@Valid @RequestBody Company comp){
        logger.trace("Saving company.....");
        Company company = companyService.saveCompany(comp);
        logger.trace("Company Saved Successfully : {}",company );
        return company;
    }

    @GetMapping("/comp")
    public List<Company> getCompanies() throws CompanyNotFoundException {
        logger.trace("Fetching all companies.....");
        List<Company> companyList = companyService.getCompanies();
        logger.trace("Companies Fetched Successfully : {}",companyList);
        return companyList;
    }

    @GetMapping("/comp/{compId}")
    public Company getCompanyById(@Valid @PathVariable("compId") Long compId) throws CompanyNotFoundException {
        logger.trace("Fetching company with ID - {}.....", compId);
        Company company = companyService.getCompanyById(compId);
        logger.trace("Company Fetched Successfully : {}", company);
        return company;
    }

    @PutMapping("/comp")
    public Company updateCompany(@RequestBody Company comp) throws CompanyNotFoundException {
        logger.trace("Updating company.....");
        Company company = companyService.updateCompany(comp);
        logger.trace("Company Updated Successfully : {}", company);
        return company;
    }

    @DeleteMapping("/comp/{compId}")
    public ResponseEntity<ResponseMessage> deleteCompany(@Valid @PathVariable("compId") Long compId) throws CompanyNotFoundException {
        logger.trace("Deleting company with ID - {}.....", compId);
        companyService.deleteCompany(compId);
        logger.trace("Company Deleted Successfully");
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseMessage(Boolean.TRUE, "Company with Id " + compId + " Deleted Successfully"));
    }
}