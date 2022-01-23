package com.example.utubeclone.repository;

import com.example.utubeclone.models.AuthRole;
import com.example.utubeclone.models.RoleName;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface AuthRoleRepository extends MongoRepository<AuthRole, String> {
    Optional<AuthRole> findByName(RoleName name);
}
