package com.kaamcube.truelysell.model.entity;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity(name="vendor_Availability")
public class VendorAvailability {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name= "id")
    private Long id;
    @Column(name= "vendorId")
    private Long vendorId;
    @Column(name= "day")
    private String day;
    @Column(name= "fromDate")
    private String fromDate;
    @Column(name= "toDate")
    private String toDate;
}
