package com.kaamcube.truelysell.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.kaamcube.truelysell.model.entity.Vendor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface VendorRepo extends JpaRepository<Vendor, Long>{
    Optional<Vendor> findByMobileNumber(String mobileNo);
//    @Query(value = "SELECT*FROM Vendor v WHERE "+"v.name LIKE CONCAT('%',:query,'%')"+"v.email LIKE CONCAT('%',:query,'%')",nativeQuery = true)
//    List<Vendor> searchVendor(String query);

}
