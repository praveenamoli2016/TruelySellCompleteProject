package com.kaamcube.truelysell.model.entity;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.HashSet;
import java.util.Set;

@Data
@Entity(name="vendor")
public class Vendor {
	
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
	
	@Column(name= "password")
    private String password;
	
	@Column(name= "country_code")
    private Long countryCode;
	
	@Column(name= "mobile_number", unique=true)
    private String mobileNumber;

	@Column(name = "otp")
	private String otp;

	@Column(name= "date_of_birth")
    private String dateOfBirth;

	@Column(name = "terms_condition")
	private Boolean termsAndCondition;

	@Column(name= "address")
    private String address;
	
	@Column(name= "country")
    private String country;
    
	@Column(name= "state")
	private String state;
    
	@Column(name= "city")
    private String city;
	
	@Column(name= "postal_code")
    private Long postalCode;
	
	@Column(name= "account_holder_name")
    private String accountHolderName;
	
	@Column(name= "bank_name")
    private String bankName;
	
	@Column(name= "bank_address")
    private String bankAddress;
	
	@Column(name= "ifsc_code")
    private String iFSCCode;
	
	@Column(name= "pan_no")
    private String panNo;
	
	@Column(name= "sort_code")
    private String sortCode;
	
	@Column(name= "routing_no")
    private String routingNo;
	
	@Column(name= "account_email_id")
    private String acountEmailId;
	
	@Column(name= "contact_no")
    private String contactNo;
	
	@Column(name= "payment_mode")
    private String paymentmode;
	
	@Column(name= "payment_purchage")
    private String paymentPurchage;

	
	@Column(name = "created_date")
	private String createdDate;
	
	@Column(name = "updated_date")
	private String updatedDate;

	@JsonIdentityReference(alwaysAsId=true)
	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	@OneToOne(mappedBy = "vendor")
	private Subscription subscription;

	@JsonIdentityReference(alwaysAsId=true)
	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	@OneToMany(mappedBy = "vendor")
	private Set<VendorServices> vendorServices;

	@ManyToMany(cascade = CascadeType.ALL,fetch = FetchType.EAGER)
	@JoinTable(
			name = "vendor_role",
			joinColumns = @JoinColumn(name = "vendor",referencedColumnName = "id"),
			inverseJoinColumns = @JoinColumn(name = "role",referencedColumnName = "id"))
	private Set<Role> roleSet=new HashSet<>();
}
