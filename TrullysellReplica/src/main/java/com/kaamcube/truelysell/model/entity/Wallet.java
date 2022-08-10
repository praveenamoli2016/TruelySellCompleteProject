package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.kaamcube.truelysell.utility.enums.AddWallet;
import com.kaamcube.truelysell.utility.enums.PaymentMethod;
import com.kaamcube.truelysell.utility.enums.Status;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
@Getter
@Setter
@Entity
@Table(name = "wallet")
public class Wallet {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @JsonIdentityReference(alwaysAsId=true)
    @OneToOne
    @JoinColumn(name = "customer_id", nullable = false)
    private Customer customer;

    @Column(name = "balance")
    private Double Balance;

    @Column(name = "total_credit")
    private Double totalCredit;

    @Column(name = "total_debit")
    private Double totalDebit;

    @Column(name = "status")
    private Status status;

    @Column(name = "created_at")
    private String createdAt;

    @Column(name = "updated_at")
    private String updatedAt;
}
