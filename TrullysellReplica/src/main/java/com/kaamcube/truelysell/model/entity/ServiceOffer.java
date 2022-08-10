
package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Data
@Entity(name = "service_offer")
public class ServiceOffer {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(name = "service_offered")
    private String serviceOffered;

    @Column(name = "created_at")
    private String createdAt;

    @Column(name = "updated_at")
    private String updatedAt;

    @JsonIdentityReference(alwaysAsId=true)
    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "vendor_service_id", referencedColumnName = "id")
    private VendorServices vendorServices;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ServiceOffer )) return false;
        return id != null && id.equals(((ServiceOffer) o).getId());
    }
    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
