package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.BookedServices;
import com.kaamcube.truelysell.model.entity.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BookedServicesRepo extends JpaRepository<BookedServices, Long> {
    List<BookedServices> findByCustomer(Customer customer);
}
