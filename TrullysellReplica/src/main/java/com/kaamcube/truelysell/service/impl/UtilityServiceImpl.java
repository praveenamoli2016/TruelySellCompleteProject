package com.kaamcube.truelysell.service.impl;

import com.kaamcube.truelysell.model.entity.Category;
import com.kaamcube.truelysell.model.entity.SubCategory;
import com.kaamcube.truelysell.model.entity.Subscription;
import com.kaamcube.truelysell.model.entity.SubscriptionsPlan;
import com.kaamcube.truelysell.model.request.AddSubscriptionsRequest;
import com.kaamcube.truelysell.model.request.CategoryRequest;
import com.kaamcube.truelysell.model.request.SubCategoryRequest;
import com.kaamcube.truelysell.model.responce.Response;
import com.kaamcube.truelysell.repository.CategoryRepo;
import com.kaamcube.truelysell.repository.SubCategoryRepo;
import com.kaamcube.truelysell.repository.SubscriptionsPlanRepo;
import com.kaamcube.truelysell.service.UtilityService;
import com.kaamcube.truelysell.utility.enums.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class UtilityServiceImpl implements UtilityService {

    @Autowired
    private SubscriptionsPlanRepo subscriptionsPlanRepo;

    @Autowired
    private CategoryRepo categoryRepo;

    @Autowired
    private SubCategoryRepo subCategoryRepo;

    @Override
    public Response getSubscriptionsPlan() {
        Response response = null;
        try {
            List<SubscriptionsPlan> subscriptionsPlans = subscriptionsPlanRepo.findAll();
            response = new Response("Success", "200", "Subscriptions Plans List ", subscriptionsPlans);
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response addSubscriptionPlans(AddSubscriptionsRequest addSubscriptionsRequest) {
        Response response = null;
        try {
            SubscriptionsPlan subscriptionsPlan = new SubscriptionsPlan();
            subscriptionsPlan.setPlanName(addSubscriptionsRequest.getPlanName());
            subscriptionsPlan.setAmount(addSubscriptionsRequest.getAmount());
            subscriptionsPlan.setDuration(addSubscriptionsRequest.getDuration());
            subscriptionsPlan.setExpiration(addSubscriptionsRequest.getDuration());
            subscriptionsPlan.setActive(true);
            subscriptionsPlan.setCreatedAt(LocalDateTime.now().toString());
            SubscriptionsPlan subscriptionsPlanData = subscriptionsPlanRepo.save(subscriptionsPlan);
            response = new Response("Success", "201", "Add Subscriptions Plans Successfully ", subscriptionsPlanData);
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response addCategory(CategoryRequest categoryRequest) {
        Response response = null;
        try {
            if (categoryRequest.getId()!=null) {
                //getting category details
                Optional<Category> optionalCategory = this.categoryRepo.findById(categoryRequest.getId());
                if (optionalCategory.isPresent()) {
                    Category category = optionalCategory.get();
                    category.setName(categoryRequest.getName());
                    category.setStatus(categoryRequest.getStatus());
                    category.setUpdatedAt(LocalDateTime.now().toString());
                    //saving data in database
                    Category updatedCategory = categoryRepo.save(category);
                    //sending response
                    response = new Response("Success", "200", "CategoryId Details ", updatedCategory);
                } else
                    throw new Exception("Category not found");
            } else {
                Category category=new Category();
                category.setName(categoryRequest.getName());
                category.setStatus(categoryRequest.getStatus());
                category.setCreatedAt(LocalDateTime.now().toString());
                Category newCategory = categoryRepo.save(category);
                response = new Response("Success", "201", "Category added successfully ", newCategory);
            }
        } catch (Exception exception){
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response addSubCategory(SubCategoryRequest subCategoryRequest) {
        Response response=null;
        try {
            if (subCategoryRequest.getSubCategoryId()!=null) {
                Optional<SubCategory> optionalSubCategory = this.subCategoryRepo.findById(subCategoryRequest.getSubCategoryId());
                if (optionalSubCategory.isPresent()) {
                    SubCategory subCategory = optionalSubCategory.get();
                    subCategory.setName(subCategoryRequest.getName());
                    subCategory.setStatus(subCategoryRequest.getStatus());
                    subCategory.setUpdatedAt(LocalDateTime.now().toString());
                    SubCategory updatedSubCategory = subCategoryRepo.save(subCategory);
                    response = new Response("Success", "200", "Sub Category Updated Successfully", updatedSubCategory);
                } else
                    throw new Exception("Sub Category not found");
            } else {
                SubCategory subCategory=new SubCategory();
                //getting and setting category details
                Optional<Category> categoryOptional = categoryRepo.findById(subCategoryRequest.getCategoryId());
                if (categoryOptional.isPresent())
                    subCategory.setCategory(categoryOptional.get());
                else
                    throw new Exception("Category not found");
                //setting other details
                subCategory.setName(subCategoryRequest.getName());
                subCategory.setStatus(subCategoryRequest.getStatus());
                subCategory.setCreatedAt(LocalDateTime.now().toString());
                //saving in database
                SubCategory newSubCategory = subCategoryRepo.save(subCategory);
                //sending response
                response = new Response("Success", "201", "Sub Category Added successfully", newSubCategory);
            }

        }
        catch (Exception exception){
            response = new Response("Failure", "500", exception.getMessage(), null);

        }
        return response;
    }

    @Override
    public Response getAllCategory() {
        Response response=null;
        try {
            List<Category> categoryList=this.categoryRepo.findAll();
            response = new Response("Success", "200", "List of Category fetched Successfully ", categoryList);

        }
        catch (Exception exception){
            response = new Response("Failure", "500", exception.getMessage(), null);

        }
        return response;
    }

    @Override
    public Response getSubCategoryByCategoryId(Long categoryId) {
        Response response=null;
        try {
            List<SubCategory> subCategoryList=this.subCategoryRepo.findByCategoryId(categoryId);
            response = new Response("Success", "200", "CategoryId fetched Successfully ", subCategoryList);
        }
        catch (Exception exception){
            response = new Response("Failure", "500", exception.getMessage(), null);

        }
        return response;
    }

}
