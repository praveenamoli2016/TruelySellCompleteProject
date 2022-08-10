package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.VendorServices;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface VendorServiceRepo extends JpaRepository <VendorServices,Long> {
    List<VendorServices> findByVendorId(Long vendorId);
    Optional<VendorServices> findByIdAndVendorId(Long vendorServiceId, Long vendorId);
    List<VendorServices> findByServiceTitleContaining(String keyword);

//    @Query(value = "select distinct(category) from trullyshell.vendor_services;")
//    List<String> getAllCategory();
}
