package com.kaamcube.truelysell.service.impl;

import com.kaamcube.truelysell.model.entity.Customer;
import com.kaamcube.truelysell.model.entity.Vendor;
import com.kaamcube.truelysell.repository.CustomerRepo;
import com.kaamcube.truelysell.repository.VendorRepo;
import com.kaamcube.truelysell.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service(value = "userService")
public class UserServiceImpl implements UserDetailsService {

    @Autowired
    private RoleService roleService;

    @Autowired
    private CustomerRepo customerRepo;

    @Autowired
    private VendorRepo vendorRepo;

    public UserDetails loadUserByUsername(String mobileNumber) throws UsernameNotFoundException {
        Optional<Vendor> vendorOptional = vendorRepo.findByMobileNumber(mobileNumber);
        if(!vendorOptional.isPresent()){
            Optional<Customer> customerOptional = customerRepo.findByMobileNumber(mobileNumber);
            if (!customerOptional.isPresent()){
                throw new UsernameNotFoundException("Invalid mobile number or password.");
            }
            Customer customer = customerOptional.get();
            return new User(customer.getMobileNumber(), customer.getOtp(), getAuthority(customer));
        }
        Vendor vendor = vendorOptional.get();
        return new User(vendor.getMobileNumber(), vendor.getOtp(), getAuthority(vendor));
    }

    private Set<SimpleGrantedAuthority> getAuthority(Customer user) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        user.getRoleSet().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
        });
        return authorities;
    }

    private Set<SimpleGrantedAuthority> getAuthority(Vendor user) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        user.getRoleSet().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
        });
        return authorities;
    }
}
