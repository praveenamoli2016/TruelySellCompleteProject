package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.kaamcube.truelysell.utility.enums.PaymentMethod;
import com.kaamcube.truelysell.utility.enums.Status;
import lombok.Data;

import javax.persistence.*;

@Data
@Entity(name="subscription")
public class Subscription {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @JsonIdentityReference(alwaysAsId=true)
    @OneToOne
    @JoinColumn(name = "vendor_id", nullable = false)
    private Vendor vendor;

    @JsonIdentityReference(alwaysAsId=true)
    @OneToOne
    @JoinColumn(name = "plan_id", nullable = false)
    private SubscriptionsPlan subscriptionsPlan;

    @Column(name = "payment_method")
    private PaymentMethod paymentMethod;

    @Column(name = "status")
    private Status status;

    @Column(name = "created_at")
    private String createdAt;

    @Column(name = "updated_at")
    private String updatedAt;
}
