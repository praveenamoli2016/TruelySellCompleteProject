package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.WalletTransactions;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CustomerWalletTransactionsRepo extends JpaRepository<WalletTransactions,Long> {
    List<WalletTransactions> findByCustomerId(Long customerId);
}
