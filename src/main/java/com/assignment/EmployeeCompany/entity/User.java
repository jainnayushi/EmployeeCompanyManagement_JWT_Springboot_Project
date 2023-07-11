package com.assignment.EmployeeCompany.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name= "User")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;
    private String userName;
    private String password;
    private String email;
}