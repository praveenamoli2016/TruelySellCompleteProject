package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@Entity(name="customer")
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name= "id")
    private Long id;

    @NotBlank(message = "Name is mandatory")
    @Column(name= "name")
    private String name;

    @NotBlank(message = "Email is mandatory")
    @Column(name= "email")
    private String email;

    @NotBlank(message = "Password is mandatory")
    @Column(name= "password")
    private String password;

    //@NotBlank(message = "CountryCode is mandatory")
   // @Size(min = 4,max=10,message = "password must be minimum 4 charactor and maximum 10 charactor")
    @Column(name= "country_code")
    private Long countryCode;

    @NotBlank(message = "MobileNumber is mandatory")
    @Column(name= "mobile_number", unique=true)
    private String mobileNumber;

   // @NotBlank(message = "otp is mandatory")
    @Column(name = "otp")
    private String otp;

   // @NotBlank(message = "Date_of_birth is mandatory")
    @Column(name= "date_of_birth")
    private String dateOfBirth;

    @NotNull(message = "TermsAndCondition is mandatory")
    @Column(name = "terms_condition")
    private Boolean termsAndCondition;

    //@NotBlank(message = "Address is mandatory")
    @Column(name= "address")
    private String address;

    @Column(name= "country")
    private String country;

    @Column(name= "state")
    private String state;

    @Column(name= "city")
    private String city;

    //@NotBlank(message = "PostalCode is mandatory")
    @Column(name= "postal_code")
    private Long postalCode;

   // @NotBlank(message = "CreatedDate is mandatory")
    @Column(name = "created_date")
    private String createdDate;

   // @NotBlank(message = "Updated is mandatory")
    @Column(name = "updated_date")
    private String updatedDate;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @OneToOne(mappedBy = "customer")
    private BookedServices bookedServices;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @OneToOne(mappedBy = "customer")
    private Wallet wallet;

    @JsonIdentityReference(alwaysAsId=true)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @OneToMany(mappedBy = "customer")
    private List<WalletTransactions> walletTransactions;


    @ManyToMany(cascade = CascadeType.ALL,fetch = FetchType.EAGER)
    @JoinTable(
            name = "customer_role",
            joinColumns = @JoinColumn(name = "customer",referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role",referencedColumnName = "id"))
    private Set<Role> roleSet=new HashSet<>();
}
