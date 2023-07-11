package com.assignment.EmployeeCompany.repository;

import com.assignment.EmployeeCompany.entity.Company;
import com.assignment.EmployeeCompany.entity.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long> {
    List<Employee> findByCompany(Company company);
}
