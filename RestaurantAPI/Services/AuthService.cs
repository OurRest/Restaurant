using AutoMapper;
using Microsoft.EntityFrameworkCore;
using RestaurantAPI.Entity;
using RestaurantAPI.Helpers;
using RestaurantAPI.Interfaces;
using RestaurantAPI.Models;
using BCrypt.Net;
using NuGet.Common;

namespace RestaurantAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly RestaurantDbContext _restaurantDbContext;
        private readonly IMapper _mapper;
        private readonly JwtTokenService _jwtTokenService;

        public AuthService(RestaurantDbContext restaurantDbContext, IMapper mapper, IConfiguration configuration, JwtTokenService jwtTokenService) {
            _restaurantDbContext = restaurantDbContext;
            _mapper = mapper;
            _jwtTokenService = jwtTokenService;
        }

        public async Task<APIResponse> Login(LoginRequestDto loginRequest)
        {
            var response = new APIResponse();

            try
            {

                var user = await _restaurantDbContext.Users.FirstOrDefaultAsync(x => x.Email == loginRequest.Email);

                if (user == null)
                {
                    response.StatusCode = 404;
                    response.ResponseMessage = "User does not exist";
                    return response;
                }

                else
                {
                    var NotHashedPassword = BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.Password);
                    if (user == null || NotHashedPassword == false)
                    {
                        response.StatusCode = 404;
                        response.ResponseMessage = "Incorrect Email or Password.";
                        return response;
                    }

                    user.LastLoggedIn = DateTime.Now; // Update LastLoggedIn property
                    await _restaurantDbContext.SaveChangesAsync(); // Save changes
                    var token = _jwtTokenService.GenerateJwtToken(user);

                    response.StatusCode = 200;
                    response.ResponseMessage = "Login Successful.";
                    response.Data = new { user, token };
                    return response;
                }
            }
            catch (Exception ex)
            {

                response.ResponseMessage = "An error occurred while trying to login.";
                response.StatusCode = 500; // Internal Server Error
                response.ErrorMessage = ex.Message;
                return response;
            }



        }



        private string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);

        }

        //public Task<APIResponse> Login(string email, string password)
        //{
        //    var response = new APIResponse();   

        //}

        public async Task<APIResponse> Register(UserDTO userDTO)
        {

            var response =  new APIResponse();
            var emailExist = await _restaurantDbContext.Users.FirstOrDefaultAsync(p => p.Email == userDTO.Email);
            var phoneExist = await _restaurantDbContext.Users.FirstOrDefaultAsync(p => p.PhoneNo == userDTO.PhoneNo);


            if (emailExist != null)
            {
                response.ResponseMessage = "User with this Email already exists.";
                response.StatusCode = 400;
                return response;
            }
            if(phoneExist != null)
            {
                response.ResponseMessage = "User with this Phone Number already exists";
                response.StatusCode = 400;
                return response;
            }

            var entity = new User
            {

                Email = userDTO.Email,
                PhoneNo = userDTO.PhoneNo,
                Address = userDTO.Address,
                Gender = userDTO.Gender,
                State = userDTO.State,
                Country = userDTO.Country,
                FirstName = userDTO.FirstName,
                LastName = userDTO.LastName,
                Role = "Customer",
                Status = "Active",
                RegisteredDate = DateTime.Now,
                Password = HashPassword(userDTO.Password),
                DateOfBirth = userDTO.DateOfBirth,


            };

            try
            {
                _restaurantDbContext.Add(entity);
                await _restaurantDbContext.SaveChangesAsync();

                response.ResponseMessage = "Registration Successful";
                response.StatusCode = 200;
                response.Data = userDTO;
                return response;
            }
            catch (Exception ex)
            {

                response.ResponseMessage = "An error occurred during registration.";
                response.StatusCode = 500; // Internal Server Error
                response.ErrorMessage = ex.Message; 
                return response;
            }
        }

    }
}
