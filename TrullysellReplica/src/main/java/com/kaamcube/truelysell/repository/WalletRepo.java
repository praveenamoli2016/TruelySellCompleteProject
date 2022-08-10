package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.Customer;
import com.kaamcube.truelysell.model.entity.Wallet;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface WalletRepo extends  JpaRepository<Wallet, Long>{
    Optional<Wallet> findByCustomerId(Long customerId);
}
