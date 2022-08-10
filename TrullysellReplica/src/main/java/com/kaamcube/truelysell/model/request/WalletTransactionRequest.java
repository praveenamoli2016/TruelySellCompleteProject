package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.model.entity.Customer;
import com.kaamcube.truelysell.utility.enums.Status;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WalletTransactionRequest {
    @NotBlank(message = "Id not null")
    private Long id;
    @NotBlank(message = "CustomerId not null")
    private Customer customer;
    @NotBlank(message = "SrNo not null")
    private int srNo;
    @NotBlank(message = "Date not null")
    private Double date;
    @NotBlank(message = "Wallet not null")
    private Double wallet;
    @NotBlank(message = "Credit not null")
    private Double credit;
    @NotBlank(message = "Debit not null")
    private Double debit;
    @NotBlank(message = "TxtAmount not null")
    private Double txtAmount;
    @NotBlank(message = "Available not null")
    private Status available;
    private String reason;
    @NotBlank(message = "Status not null")
    private String status;
}
