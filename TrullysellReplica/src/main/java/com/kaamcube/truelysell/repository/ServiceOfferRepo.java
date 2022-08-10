package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.ServiceOffer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Set;

@Repository
public interface ServiceOfferRepo extends JpaRepository<ServiceOffer, Long> {
    @Query(value = "Select * from service_offer where vendor_service_id = :id", nativeQuery = true)
    Set<ServiceOffer> findByVendorServiceId(@Param("id") Long vendorServiceId);
//    Set<ServiceOffer> findByVendorServiceId(Long id);
}
