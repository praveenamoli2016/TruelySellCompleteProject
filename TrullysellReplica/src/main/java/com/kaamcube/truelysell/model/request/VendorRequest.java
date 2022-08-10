package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import javax.persistence.Column;
import javax.validation.constraints.NotBlank;
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VendorRequest {
    private Long id;
    @NotBlank(message = "Name is mandatory")
    private String name;
    @NotBlank(message = "Email is mandatory")
    private String email;
    @NotBlank(message = "Password is mandatory")
    private String password;
    @NotBlank(message = "CountryCode is notNull")
    private Long countryCode;
    @NotBlank(message = "Mobile number mandatory")
    private String mobileNumber;
    @NotBlank(message = "OTP is mandatory")
    private String otp;
    @NotBlank(message = "DateOfBirth is notNull")
    private String dateOfBirth;
    @NotBlank(message = "TermsAndCondition is mandatory")
    private Boolean termsAndCondition;
    @NotBlank(message = "Address is notNull")
    private String address;
    @NotBlank(message = "Country is notNull")
    private String country;
    @NotBlank(message = "State is notNull")
    private String state;
    @NotBlank(message = "City is notNull")
    private String city;
    @NotBlank(message = "PostalCode is mandatory")
    private Long postalCode;
    @NotBlank(message = "AccountHolderName is mandatory")
    private String accountHolderName;
    @NotBlank(message = "BankName is mandatory")
    private String bankName;
    @NotBlank(message = "BankAddress is mandatory")
    private String bankAddress;
    @NotBlank(message = "IFSCCode is mandatory")
    private String iFSCCode;
    @NotBlank(message = "PanNo is mandatory")
    private String panNo;
    @NotBlank(message = "SortCode is mandatory")
    private String sortCode;
    @NotBlank(message = "RoutingNo is mandatory")
    private String routingNo;
    @NotBlank(message = "AccountEmailId is mandatory")
    private String accountEmailId;
    @NotBlank(message = "ContactNo is mandatory")
    private String contactNo;
    @NotBlank(message = "PaymentMode is mandatory")
    private String paymentMode;
    @NotBlank(message = "PaymentPurchase is mandatory")
    private String paymentPurchase;
}
