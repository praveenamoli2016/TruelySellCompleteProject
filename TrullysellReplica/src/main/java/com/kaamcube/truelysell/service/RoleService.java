package com.kaamcube.truelysell.service;

import com.kaamcube.truelysell.model.entity.Role;

public interface RoleService {
    Role findByName(String name);
}
