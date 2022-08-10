package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.model.entity.SubscriptionsPlan;
import com.kaamcube.truelysell.model.entity.Vendor;
import com.kaamcube.truelysell.utility.enums.PaymentMethod;
import lombok.Data;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SubscriptionRequest {
    @NotBlank(message = "VendorId is notNull")
    private Long vendorId;
    @NotBlank(message = "PlanId is notNull")
    private Long planId;
    @NotBlank(message = "PaymentMethod is mandatory")
    private PaymentMethod paymentMethod;

}
