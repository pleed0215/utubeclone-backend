package com.example.utubeclone.models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Objects;

@Document(collection = "roles")
public class AuthRole {
    @Id
    private String id;

    private RoleName name;

    public AuthRole(RoleName name) {
        this.name = name;
    }

    public AuthRole() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public RoleName getName() {
        return name;
    }

    public void setName(RoleName name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "AuthRole{" +
                "id='" + id + '\'' +
                ", name=" + name +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthRole authRole = (AuthRole) o;
        return Objects.equals(id, authRole.id) && name == authRole.name;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name);
    }

}
