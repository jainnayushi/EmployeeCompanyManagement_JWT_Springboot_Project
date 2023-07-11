package com.assignment.EmployeeCompany.service;

import com.assignment.EmployeeCompany.exception.CompanyNotFoundException;
import com.assignment.EmployeeCompany.exception.CustomException;
import com.assignment.EmployeeCompany.entity.Company;
import com.assignment.EmployeeCompany.repository.CompanyRepository;
import com.assignment.EmployeeCompany.repository.EmployeeRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CompanyServiceImpl implements CompanyService {
    @Autowired
    private CompanyRepository companyRepo;

    @Autowired
    private EmployeeRepository employeeRepo;

    private Logger logger = LoggerFactory.getLogger(CompanyServiceImpl.class);
    @Override
    public Company saveCompany(Company comp) {
        return companyRepo.save(comp);
    }

    @Override
    public List<Company> getCompanies() throws CompanyNotFoundException {
        if (companyRepo.findAll().isEmpty()) {
            throw new CompanyNotFoundException("Company Not Found");
        }
        return companyRepo.findAll();
    }

    @Override
    public Company getCompanyById(Long compId) throws CompanyNotFoundException {
        if (companyRepo.findById(compId).isEmpty()) {
            throw new CompanyNotFoundException("Company with id " + compId + " not available");
        }
        return companyRepo.findById(compId).get();
    }

    @Override
    public Company updateCompany(Company comp) throws CompanyNotFoundException {
            if (comp.getCompId() == null) {
                throw new CustomException("Company Id is required");
            }
            Long compId = comp.getCompId();
            Company compDB = companyRepo.findById(compId)
                    .orElseThrow(() -> new CompanyNotFoundException("Company with id " + compId + " not available"));
            compDB.setCompName(comp.getCompName());
            return companyRepo.save(compDB);

    }

    @Override
    public void deleteCompany(Long compId) throws CompanyNotFoundException {
        Company companyDB = companyRepo.findById(compId)
                .orElseThrow(()-> new CompanyNotFoundException("Company with id " + compId + " not available to be deleted"));

        if(!employeeRepo.findByCompany(companyDB).isEmpty()){
            throw new CustomException("Deletion Failed : Since, Employees associated with Company of Id-" + compId + " exists");
        }
        companyRepo.deleteById(compId);

    }
}