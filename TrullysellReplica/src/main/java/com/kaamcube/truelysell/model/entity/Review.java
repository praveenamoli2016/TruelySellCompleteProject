package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "review")
public class Review {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id",unique = true,nullable = false)
    private Long id;

    @Column(name = "reviewer_id",nullable = false,length = 1500)
    private Long reviewerId;

    @Column(name = "comment",nullable = false,length = 1500)
    private String comment;

    @Column(name = "rating",nullable = true)
    private Integer rating;

    @Column(name = "created_date",nullable = true)
    private String createdDate;

    @Column(name = "updated_date")
    private String updatedDate;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @ManyToOne
    @JoinColumn(name = "vendorServices")
    private VendorServices vendorServices;

}
