package com.assignment.EmployeeCompany.repository;


import com.assignment.EmployeeCompany.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Integer>{
    User findByUserName(String username);
}
