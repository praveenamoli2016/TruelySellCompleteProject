package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.persistence.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Data
@Entity(name="vendor_services")
public class VendorServices {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name= "id")
    private Long id;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "vendor_id")
    private Vendor vendor;

    @Column(name= "service_title")
    private String serviceTitle;

    @Column(name= "service_amount")
    private String serviceAmount;

    @Column(name= "service_location")
    private String serviceLocation;

//    @Column(name= "category")
//    private String category;
//
//    @Column(name= "sub_category")
//    private String subcategory;

//    @OneToMany
//    @JoinColumn(name = "vendor_service_id")
    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @OneToMany(mappedBy = "vendorServices", cascade = CascadeType.ALL)
    private Set<ServiceOffer> serviceOffered = new HashSet<>();;

    public void addService(ServiceOffer serviceOffer){
        serviceOffered.add(serviceOffer);
        serviceOffer.setVendorServices(this);
    }
    public void removeService(ServiceOffer serviceOffer){
        serviceOffered.remove(serviceOffer);
        serviceOffer.setVendorServices(null);
    }

    @Column(name= "descriptions")
    private String descriptions;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @OneToOne(mappedBy = "vendorServices")
    private BookedServices bookedServices;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @ManyToOne
    @JoinColumn(name = "category_id", nullable = false)
    private Category category;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @ManyToOne
    @JoinColumn(name = "sub_category_id", nullable = false)
    private SubCategory subCategory;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @OneToMany(mappedBy = "vendorServices",fetch = FetchType.LAZY)
    private Set<Review> reviews;
}
