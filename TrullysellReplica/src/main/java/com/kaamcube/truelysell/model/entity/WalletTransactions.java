package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.kaamcube.truelysell.utility.enums.Status;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
    @Getter
    @Setter
    @Entity
    @Table(name = "wallet_transactions")
    public class WalletTransactions {
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        private Long id;

        @JsonIdentityReference(alwaysAsId=true)
        @ManyToOne
        @JoinColumn(name = "customer_id", nullable = false)
        private Customer customer;

        @Column(name = "date")
        private String date;

        @Column(name = "wallet")
        private Double wallet;

        @Column(name = "credit")
        private Boolean credit;

        @Column(name = "debit")
        private Boolean debit;

        @Column(name = "txt_amount")
        private Double txtAmount;

        @Column(name = "available")
        private Double available;

        @Column(name = "reason")
        private String reason;

        @Column(name = "status")
        private Status status;

        @Column(name = "created_at")
        private String createdAt;

        @Column(name = "updated_at")
        private String updatedAt;
}
