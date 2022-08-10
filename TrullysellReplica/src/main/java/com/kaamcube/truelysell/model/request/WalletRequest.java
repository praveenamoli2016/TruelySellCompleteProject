package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.model.entity.Customer;
import com.kaamcube.truelysell.utility.enums.Status;
import lombok.Data;

import javax.persistence.Column;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WalletRequest {
    @NotBlank(message = "Id not null")
    private Long id;
    @NotBlank(message = "Customer not null")
    private Customer customer;
    @NotBlank(message = "Balance not null")
    private Double Balance;
    @NotBlank(message = "TotalCredit not null")
    private Double totalCredit;
    @NotBlank(message = "TotalDebit not null")
    private Double totalDebit;
    @NotBlank(message = "Status not null")
    private Status status;
    @NotBlank(message = " not null")
    private String created;
    @NotBlank(message = " not null")
    private String updated;

}
