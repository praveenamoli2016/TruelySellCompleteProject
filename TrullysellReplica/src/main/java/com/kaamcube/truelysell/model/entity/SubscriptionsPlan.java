package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.kaamcube.truelysell.utility.enums.Plan;
import lombok.Data;

import javax.persistence.*;

@Data
@Entity(name="subscription_plan")
public class SubscriptionsPlan {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name="plan_name",unique = true)
    private Plan planName;

    @Column(name = "amount")
    private Double amount;

    @Column(name = "duration_in_day")
    private Long duration;

    @Column(name = "expired_in_day")
    private Long expiration;

    @Column(name = "active")
    private Boolean active;

    @Column(name = "created_at")
    private String createdAt;

    @Column(name = "updated_at")
    private String updatedAt;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @OneToOne(mappedBy = "subscriptionsPlan")
    private Subscription subscription;

}
