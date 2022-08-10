package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.utility.enums.PaymentMethod;
import com.kaamcube.truelysell.utility.enums.Plan;
import com.kaamcube.truelysell.utility.enums.Status;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AddSubscriptionsRequest {
    @NotBlank(message = "PlanName is notNull")
    private Plan planName;
    @NotBlank(message = "Duration is notNull")
    private Long duration;;
    @NotBlank(message = "Amount is notNull")
    private Double amount;
}
