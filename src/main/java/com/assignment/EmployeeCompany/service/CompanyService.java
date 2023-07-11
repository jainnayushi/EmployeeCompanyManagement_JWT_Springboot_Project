package com.assignment.EmployeeCompany.service;

import com.assignment.EmployeeCompany.entity.Company;
import com.assignment.EmployeeCompany.exception.CompanyNotFoundException;

import java.util.List;

public interface CompanyService {
    public Company saveCompany(Company comp);

    public List<Company> getCompanies() throws CompanyNotFoundException;

    public Company getCompanyById(Long compId) throws CompanyNotFoundException;

    public Company updateCompany(Company comp) throws CompanyNotFoundException;

    public void deleteCompany(Long compId) throws CompanyNotFoundException;

}
