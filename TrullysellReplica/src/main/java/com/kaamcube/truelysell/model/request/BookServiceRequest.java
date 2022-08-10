package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.utility.enums.PaymentMethod;
import com.kaamcube.truelysell.utility.enums.Status;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BookServiceRequest {
    //@NotBlank(message = "Customer is notNull")
    private Long customerId;
    //@NotBlank(message = "ServiceId is notNull")
    private Long serviceId;
    @NotBlank(message = "ServiceLocation is mandatory")
    private String serviceLocation;
    @NotBlank(message = "ServiceAmount is notNull")
    private String serviceAmount;
    @NotBlank(message = "Date is notNull")
    private String date;
    @NotBlank(message = "TimeSlot is mandatory")
    private String timeSlot;
    @NotBlank(message = "Notes is notNull")
    private String notes;
    //@NotBlank(message = "PlanName is mandatory")
    private PaymentMethod paymentMethod;
    //@NotBlank(message = "Status is mandatory")
    private Status status;
}
