package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.model.entity.Category;
import com.kaamcube.truelysell.utility.enums.Status;
import jdk.nashorn.internal.ir.annotations.Ignore;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SubCategoryRequest {

    @Ignore
    private Long subCategoryId;

    @NotNull(message = "Category is mandatory")
    private Long categoryId;

    @NotBlank(message = "Name is mandatory")
    private String name;

    @NotNull(message = "Status is NotNull")
    private Boolean status;

}
