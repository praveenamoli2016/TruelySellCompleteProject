package com.kaamcube.truelysell.service;

import com.kaamcube.truelysell.model.request.AddSubscriptionsRequest;
import com.kaamcube.truelysell.model.request.CategoryRequest;
import com.kaamcube.truelysell.model.request.SubCategoryRequest;
import com.kaamcube.truelysell.model.responce.Response;

public interface UtilityService {
    Response getSubscriptionsPlan();

    Response addSubscriptionPlans(AddSubscriptionsRequest addSubscriptionsRequest);

    Response addCategory(CategoryRequest categoryRequest);

    Response addSubCategory(SubCategoryRequest subCategoryRequest);

    Response getAllCategory();

    Response getSubCategoryByCategoryId(Long id);
}
