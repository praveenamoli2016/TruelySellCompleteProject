package com.kaamcube.truelysell.model.responce;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CustomerRegisterResponse {
    private Long id;
    private String name;
    private String email;
    private String password;
    private String mobileNo;
    private Boolean termsAndCondition;
    private String createdDate;
    private String updatedDate;
}
