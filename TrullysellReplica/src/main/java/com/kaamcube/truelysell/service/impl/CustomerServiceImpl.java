package com.kaamcube.truelysell.service.impl;

import com.kaamcube.truelysell.model.entity.*;
import com.kaamcube.truelysell.model.request.*;
import com.kaamcube.truelysell.model.responce.CustomerRegisterResponse;
import com.kaamcube.truelysell.model.responce.Response;
import com.kaamcube.truelysell.repository.*;
import com.kaamcube.truelysell.service.CustomerService;
import com.kaamcube.truelysell.service.RoleService;
import com.kaamcube.truelysell.utility.TruelySellUtility;
import com.kaamcube.truelysell.utility.enums.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.awt.print.Pageable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class CustomerServiceImpl implements CustomerService {

    @Autowired
    private CustomerRepo customerRepo;

    @Autowired
    private BookedServicesRepo bookedServicesRepo;

    @Autowired
    private WalletRepo walletRepo;

    @Autowired
    private CustomerWalletTransactionsRepo customerWalletTransactionsRepo;

    @Autowired
    private RoleService roleService;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Override
    public Response registerCustomer(RegistrationRequest customerRequest) {
        Response response = null;
        try {
            //preparing vendor details
            Customer customer = new Customer();
            customer.setName(customerRequest.getName());
            customer.setMobileNumber(customerRequest.getMobileNo());
            customer.setEmail(customerRequest.getEmail());
            customer.setPassword(customerRequest.getPassword());
            customer.setTermsAndCondition(customerRequest.getTermsAndCondition());
            customer.setCreatedDate(LocalDateTime.now().toString());

            //Assigning role to customer
            Role role = roleService.findByName("CUSTOMER");
            Role role2 = roleService.findByName("ADMIN");
            Set<Role> roleSet = new HashSet<>();
            roleSet.add(role);
            roleSet.add(role2);
            customer.setRoleSet(roleSet);

            //saving vendor details on database
            Customer customerData = customerRepo.save(customer);

            //preparing response
            CustomerRegisterResponse customerRegisterResponse = new CustomerRegisterResponse(customerData.getId(),customerData.getName(), customerData.getEmail(), customerData.getPassword(),
                    customerData.getMobileNumber(), customerData.getTermsAndCondition(), customerData.getCreatedDate(), customerData.getUpdatedDate());

            //preparing response for sending back
            response = new Response("Success", "201", "Customer added successfully", customerRegisterResponse);

            //sending otp to verify mobile no and save otp in data for future validation
            String otp = TruelySellUtility.sendOTP(customerData.getMobileNumber());
            customerData.setOtp(encoder.encode(otp));
            //updating otp in Database
            customerRepo.save(customerData);

            //create a wallet for customer
            createWallet(customerData);
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    private Wallet createWallet(Customer customerData) {
        //create a wallet for customer
        Wallet wallet = new Wallet();
        wallet.setCustomer(customerData);
        wallet.setBalance(0.0);
        wallet.setTotalCredit(0.0);
        wallet.setTotalDebit(0.0);
        wallet.setStatus(Status.ACTIVE);
        wallet.setCreatedAt(LocalDateTime.now().toString());
        return walletRepo.save(wallet);
    }

    @Override
    public Response otpValidation(OtpRequest otpRequest) {
        Response response = null;
        try {
            Optional<Customer> customerOptional = customerRepo.findByMobileNumber(otpRequest.getMobileNo());
            if (customerOptional.isPresent()) {
                Customer customer = customerOptional.get();
                if (customer.getOtp().equals(otpRequest.getOtp())) {
                    response = new Response("Success", "200", "otp verified", null);
                } else {
                    response = new Response("Failure", "401", "otp mismatched", null);
                }
            } else {
                response = new Response("Failure", "404", "Customer not found with given mobile number", null);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response customerLogin(LoginRequest loginRequest) {
        Response response = null;
        try {
            Optional<Customer> customerOptional = customerRepo.findByMobileNumber(loginRequest.getMobileNo());
            if (customerOptional.isPresent()) {
                Customer customer = customerOptional.get();
                String otp = TruelySellUtility.sendOTP(customer.getMobileNumber());
                customer.setOtp(otp);
                //updating otp in Database
                customerRepo.save(customer);
                response = new Response("Success", "200", "otp sent successfully", null);
            } else {
                response = new Response("Failure", "404", "Vendor not found with given mobile number", null);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getCustomer(Long customerId) {
        Response response = null;
        try {
            Optional<Customer> customerOptional = customerRepo.findById(customerId);
            if (customerOptional.isPresent()) {
                Customer customer = customerOptional.get();
                response = new Response("Success", "200", "Customer fetched successfully", customer);
            } else {
                response = new Response("Failure", "404", "Customer not found ", null);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response updateCustomer(CustomerRequest customerRequest) {
        Response response = null;
        try {
            Optional<Customer> customerOptional = customerRepo.findById(customerRequest.getId());
            if (customerOptional.isPresent()) {
                Customer customer = customerOptional.get();
                //preparing vendor details
                customer.setName(customerRequest.getName());
                customer.setMobileNumber(customerRequest.getMobileNumber());
                customer.setEmail(customerRequest.getEmail());
                customer.setPassword(customerRequest.getPassword());
                customer.setTermsAndCondition(customerRequest.getTermsAndCondition());
                customer.setAddress(customerRequest.getAddress());
                customer.setCountry(customerRequest.getCountry());
                customer.setCountryCode(customerRequest.getCountryCode());
                customer.setDateOfBirth(customerRequest.getDateOfBirth());
                customer.setState(customerRequest.getState());
                customer.setCity(customerRequest.getCity());
                customer.setPostalCode(customerRequest.getPostalCode());
                customer.setUpdatedDate(LocalDateTime.now().toString());
                //saving vendor details on database
//                List<Customer> list = new ArrayList<>() ;
//                customerRepo.saveAll(list);
                Customer updatedCustomerData = customerRepo.save(customer);
                response = new Response("Success", "200", "Vendor updated ", updatedCustomerData);
            } else {
                response = new Response("Failure", "404", "Vendor not found ", null);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Autowired
    private VendorServiceRepo vendorServiceRepo;

    @Override
    public Response bookService(BookServiceRequest bookServiceRequest) {
        Response response = null;
        try {
            BookedServices bookedServices = new BookedServices();

            //fetching customer details
            Optional<Customer> customer = customerRepo.findById(bookServiceRequest.getCustomerId());
            if (customer.isPresent())
                bookedServices.setCustomer(customer.get());
            else
                throw new Exception("Customer not found");

            //fetching service details
            Optional<VendorServices> vendorServices = vendorServiceRepo.findById(bookServiceRequest.getServiceId());
            if (vendorServices.isPresent())
                bookedServices.setVendorServices(vendorServices.get());
            else
                throw new Exception("Service not found");

            //preparing data to save in database
            bookedServices.setServiceAmount(bookServiceRequest.getServiceAmount());
            bookedServices.setServiceLocation(bookServiceRequest.getServiceLocation());
            bookedServices.setDate(bookServiceRequest.getDate());
            bookedServices.setNotes(bookServiceRequest.getNotes());
            bookedServices.setPaymentMethod(bookServiceRequest.getPaymentMethod());
            bookedServices.setTimeSlot(bookServiceRequest.getTimeSlot());
            bookedServices.setStatus(bookServiceRequest.getStatus());
            //saving data in database
            BookedServices bookedService = bookedServicesRepo.save(bookedServices);
            //sending response
            response = new Response("Success", "201", "Service Booked Successfully", bookedService);
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getCustomerBooking(Long customerId) {
        Response response = null;
        try {
            Optional<Customer> customer = customerRepo.findById(customerId);
            if (customer.isPresent()) {
                List<BookedServices> bookedServices = bookedServicesRepo.findByCustomer(customer.get());
                response = new Response("Success", "200", "List of all Booked service", bookedServices);
            } else
                throw new Exception("Customer not found");
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getWalletAmount(Long customerId) {
        Response response = null;
        try {
            Optional<Customer> customer = customerRepo.findById(customerId);
            if (customer.isPresent()) {
                Optional<Wallet> wallet = walletRepo.findByCustomerId(customerId);
                if (wallet.isPresent()) {
                    response = new Response("Success", "200", "Wallet details ", wallet.get());
                } else {
                    Wallet newWallet = createWallet(customer.get());
                    response = new Response("Success", "200", "Wallet details ", newWallet);
                }
            } else
                throw new Exception("Customer not found");
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response addWalletAmount(AddWalletAmountRequest addWalletAmountRequest) {
        Response response = null;
        try {
            Optional<Customer> customerOptional = customerRepo.findById(addWalletAmountRequest.getCustomerId());
            if (customerOptional.isPresent()) {
                Optional<Wallet> walletOptional = walletRepo.findByCustomerId(addWalletAmountRequest.getCustomerId());
                Double balance = 0.0;
                if (walletOptional.isPresent()) {
                    Wallet wallet = walletOptional.get();
                    balance = wallet.getBalance();
                    wallet.setBalance(wallet.getBalance() + addWalletAmountRequest.getAmount());
                    wallet.setUpdatedAt(LocalDateTime.now().toString());
                    wallet = walletRepo.save(wallet);

                    //add data in wallet transaction
                    WalletTransactions walletTransactions = addWalletTransaction(balance, customerOptional.get(), addWalletAmountRequest);
                    response = new Response("Success", "200", "Wallet details ", wallet);
                } else {
                    Wallet wallet = createWallet(customerOptional.get());
                    balance = wallet.getBalance();
                    wallet.setBalance(wallet.getBalance() + addWalletAmountRequest.getAmount());
                    wallet.setUpdatedAt(LocalDateTime.now().toString());
                    wallet = walletRepo.save(wallet);

                    //add data in wallet transaction
                    WalletTransactions walletTransactions = addWalletTransaction(balance, customerOptional.get(), addWalletAmountRequest);
                    response = new Response("Success", "200", "Wallet details ", wallet);
                }
            } else
                throw new Exception("Customer not found");

        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getWalletTransaction(Long customerId) {
        Response response = null;
        try {
            Optional<Customer> customerOptional = customerRepo.findById(customerId);
            if (customerOptional.isPresent()) {
                List<WalletTransactions> walletTransactions = customerWalletTransactionsRepo.findByCustomerId(customerId);
                response = new Response("Success", "200", "Wallet Transactions details ", walletTransactions);
            } else {
                throw new Exception("Customer not found");
            }

        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }



    public WalletTransactions addWalletTransaction(Double balance, Customer customer, AddWalletAmountRequest addWalletAmountRequest) {
        WalletTransactions walletTransactions = new WalletTransactions();
        walletTransactions.setWallet(balance);
        walletTransactions.setCustomer(customer);
        walletTransactions.setTxtAmount(addWalletAmountRequest.getAmount());
        walletTransactions.setAvailable(balance + addWalletAmountRequest.getAmount());
        walletTransactions.setCredit(addWalletAmountRequest.getAmount() > 0.0);
        walletTransactions.setDebit(addWalletAmountRequest.getAmount() < 0.0);
        walletTransactions.setDate(addWalletAmountRequest.getDate());
        walletTransactions.setReason("-");
        return customerWalletTransactionsRepo.save(walletTransactions);
    }
}

