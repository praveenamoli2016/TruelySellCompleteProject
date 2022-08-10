package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.Customer;
import com.kaamcube.truelysell.model.entity.Vendor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomerRepo extends JpaRepository<Customer, Long> {

    Optional<Customer> findByMobileNumber(String mobileNumber);

}
