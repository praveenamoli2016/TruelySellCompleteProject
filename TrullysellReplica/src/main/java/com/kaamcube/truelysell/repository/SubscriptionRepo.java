package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.Subscription;
import com.kaamcube.truelysell.utility.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SubscriptionRepo extends JpaRepository<Subscription,Long> {
   Optional<Subscription> findByVendorIdAndStatus(Long vendorId, Status status);
}
