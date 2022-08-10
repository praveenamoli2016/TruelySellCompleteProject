package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.kaamcube.truelysell.utility.enums.PaymentMethod;
import com.kaamcube.truelysell.utility.enums.Status;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;

@Data
@Entity(name = "booked_services")
public class BookedServices {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @JsonIdentityReference(alwaysAsId=true)
    @OneToOne
    @JoinColumn(name = "customer_id", nullable = false)
    private Customer customer;

    @JsonIdentityReference(alwaysAsId=true)
    @OneToOne
    @JoinColumn(name = "service_id", nullable = false)
    private VendorServices vendorServices;

    @NotBlank(message = "Service is mandatory")
    @Column(name = "service_location")
    private String serviceLocation;

    @Column(name = "service_amount")
    private String serviceAmount;

    @Column(name = "date")
    private String date;

    @Column(name = "time_slot")
    private String timeSlot;

    @Column(name = "notes")
    private String notes;

    @Column(name = "payment_method")
    private PaymentMethod paymentMethod;

    @Column(name = "status")
    private  Status status;

    @Column(name = "created_at")
    private String createdAt;

    @Column(name = "updated_at")
    private String updatedAt;

}
