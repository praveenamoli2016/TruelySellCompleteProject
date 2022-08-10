package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.utility.enums.PaymentMethod;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AddWalletAmountRequest {
    @NotBlank(message = "CustomerId is notNull")
    private Long customerId;
    @NotBlank(message = "Amount is notNull")
    private Double amount;
    @NotBlank(message = "Date is mandatory")
    private String date;
    @NotBlank(message = "PaymentMethod is mandatory")
    private PaymentMethod paymentMethod;
}
