package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.VendorAvailability;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VendorAvailabilityRepo extends JpaRepository<VendorAvailability, Long> {
}
