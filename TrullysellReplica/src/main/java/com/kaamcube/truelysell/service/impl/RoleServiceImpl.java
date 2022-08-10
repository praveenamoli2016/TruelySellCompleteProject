package com.kaamcube.truelysell.service.impl;

import com.kaamcube.truelysell.model.entity.Role;
import com.kaamcube.truelysell.repository.RoleRepo;
import com.kaamcube.truelysell.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service(value = "roleService")
public class RoleServiceImpl implements RoleService {

    @Autowired
    private RoleRepo roleRepo;

    @Override
    public Role findByName(String name) {
        Optional<Role> roleOptional = roleRepo.findByName(name);
        if (roleOptional.isPresent()) {
            return roleOptional.get();
        } else {
            Role role = new Role();
            role.setName("DEFAULT");
            return role;
        }
    }
}
