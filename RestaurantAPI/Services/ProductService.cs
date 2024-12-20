﻿using AutoMapper;
using Azure;
using Microsoft.EntityFrameworkCore;
using RestaurantAPI.Entity;
using RestaurantAPI.Helpers;
using RestaurantAPI.Interfaces;
using RestaurantAPI.Models;

namespace RestaurantAPI.Services
{
    
        public class ProductService : IProductService
        {
            private readonly RestaurantDbContext _context;
            private readonly IMapper _mapper;

            public ProductService(RestaurantDbContext context, IMapper mapper)
            {
                _context = context;
                _mapper = mapper;
            }



        public async Task<APIResponse> AddProductAsync(ProductDTO productDTO)
        {
            var response = new APIResponse();

            var product = new Product
            {
                Name = productDTO.Name,
                Description = productDTO.Description,
                Category = productDTO.Category,
                CreatedByName = productDTO.CreatedByName,
                DateCreated = productDTO.DateCreated,
                CreatedByUserId = productDTO.CreatedByUserId,
                Price = productDTO.Price,
                Status = "Active",
                Thumbnail = productDTO.Thumbnail,
                Image1 = productDTO.Image1,
                Image2 = productDTO.Image2,
                Image3 = productDTO.Image3,
                Rating = productDTO.Rating,
                IsAvailable = productDTO.IsAvailable,

            };

            try
            {
                
                _context.Products.Add(product);
                await _context.SaveChangesAsync();

                response.ResponseMessage = "Product Added Successfully";
                response.StatusCode = 200;
                response.Data = productDTO; // You can adjust this as needed

                return response;
            }
            catch (Exception ex)
            {
                response.ResponseMessage = "An error occurred while adding the product";
                response.StatusCode = 500;
                response.ErrorMessage = ex.Message;
                return response;
            }
        }



        public async Task<APIResponse> UpdateProductAsync(int id, ProductDTO productDTO)
        {
            var response = new APIResponse();

            var existingProduct = await _context.Products.FindAsync(id);

            if (existingProduct == null)
            {
                response.ResponseMessage = "Product Not Found.";
                response.StatusCode = 404;
                return response;
            }

            // Check if there are any changes
            if (productDTO.Name == existingProduct.Name &&
                productDTO.Description == existingProduct.Description &&
                productDTO.Category == existingProduct.Category &&
                productDTO.Price == existingProduct.Price &&
                productDTO.Thumbnail == existingProduct.Thumbnail &&
                productDTO.Image1 == existingProduct.Image1 &&
                productDTO.Image2 == existingProduct.Image2 &&
                productDTO.Image3 == existingProduct.Image3 &&
                productDTO.Rating == existingProduct.Rating &&
                productDTO.IsAvailable == existingProduct.IsAvailable)
            {
                response.ResponseMessage = "No Changes Made.";
                response.StatusCode = 200;
                return response;
            }

            // Update the properties
            existingProduct.Name = productDTO.Name;
            existingProduct.Description = productDTO.Description;
            existingProduct.Category = productDTO.Category;
            existingProduct.Price = productDTO.Price;
            existingProduct.Thumbnail = productDTO.Thumbnail;
            existingProduct.Image1 = productDTO.Image1;
            existingProduct.Image2 = productDTO.Image2;
            existingProduct.Image3 = productDTO.Image3;
            existingProduct.Rating = productDTO.Rating;
            existingProduct.IsAvailable = productDTO.IsAvailable;
            existingProduct.LastModifiedBy = productDTO.LastModifiedBy;
            existingProduct.LastModifiedDate = DateTime.Now;

            try
            {
                await _context.SaveChangesAsync();

                response.ResponseMessage = "Product Updated Successfully.";
                response.StatusCode = 200;
                return response;
            }
            catch (Exception ex)
            {
                response.ResponseMessage = "An error occurred while updating the product.";
                response.StatusCode = 500;
                response.ErrorMessage = ex.Message;
                return response;
            }
        }


        //public async Task<APIResponse> UpdateProductAsyn1c(int id, ProductDTO productDTO)
        //{
        //    var response = new APIResponse();

        //    try
        //    {
        //        var product = await _context.Products.FindAsync(id);

        //        if (product == null)
        //        {
        //            response.ResponseMessage = "Product not found";
        //            response.StatusCode = 404;
        //            return response;
        //        }

        //        _mapper.Map(productDTO, product);
        //        await _context.SaveChangesAsync();

        //        response.ResponseMessage = "Product Updated Successfully";
        //        response.StatusCode = 200;
        //        response.Data = productDTO; 

        //        return response;
        //    }
        //    catch (Exception ex)
        //    {
        //        response.ResponseMessage = "An error occurred while updating the product";
        //        response.StatusCode = 500;
        //        response.ErrorMessage = ex.Message;
        //        return response;
        //    }
        //}

       
        
        public async Task<APIResponse> DeleteProductAsync(int id)
        {
            var response = new APIResponse();

            try
            {
                var product = await _context.Products.FindAsync(id);

                if (product == null)
                {
                    response.ResponseMessage = "Product Not Found";
                    response.StatusCode = 404;
                    return response;
                }

                _context.Products.Remove(product);
                await _context.SaveChangesAsync();

                response.ResponseMessage = "Product Deleted Successfully";
                response.StatusCode = 200;

                return response;
            }
            catch (Exception ex)
            {
                response.ResponseMessage = "An error occurred while deleting the product";
                response.StatusCode = 500;
                response.ErrorMessage = ex.Message;
                return response;
            }
        }



        public async Task<APIResponse> GetProductAsync(int id)
        {
            var response = new APIResponse();

            try
            {
                var product = await _context.Products.FindAsync(id);

                if (product == null)
                {
                    response.ResponseMessage = "Product Not Found";
                    response.StatusCode = 404;
                    return response;
                }

                var productDTO = _mapper.Map<ProductDTO>(product);

                response.ResponseMessage = "Product Found";
                response.StatusCode = 200;
                response.Data = productDTO;

                return response;
            }
            catch (Exception ex)
            {
                response.ResponseMessage = "An error occurred while retrieving the product";
                response.StatusCode = 500;
                response.ErrorMessage = ex.Message;
                return response;
            }
        }


        public async Task<APIResponse> GetAllProductsAsync(int pageNumber, int pageSize)
        {
            var response = new APIResponse();

            var totalRecords = await _context.Products.CountAsync();
            var categories = await _context.Products.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync();

            response.pageNumber = pageNumber;
            response.PageSize = pageSize;
            response.TotalRecords = totalRecords;
            response.ResponseMessage = "Success";
            response.StatusCode = 200;
            response.Data = categories;

            return response;
        }

    }

}

