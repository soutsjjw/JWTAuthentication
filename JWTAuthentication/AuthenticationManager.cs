﻿using JWTAuthentication.Contracts;
using JWTAuthentication.Models;
using JWTAuthentication.Models.DataTransferObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthentication
{
    public class AuthenticationManager : IAuthenticationManager
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;

        private ApplicationUser _user;

        public AuthenticationManager(UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        public async Task<bool> ValidateUser(UserForAuthenticationDto userForAuth)
        {
            _user = await _userManager.FindByNameAsync(userForAuth.UserName);

            return (_user != null && await _userManager.CheckPasswordAsync(_user, userForAuth.Password));
        }

        public async Task<string> CreateToken()
        {
            var signingCredentials = GetSigningCredentials();
            var claims = await GetClaims();
            var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

            return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        }

        private SigningCredentials GetSigningCredentials()
        {
            //var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SECRET"));
            var jwtSettings = _configuration.GetSection("JwtSettings").Get<JwtSettings>();
            var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);
            var secret = new SymmetricSecurityKey(key);

            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        private async Task<List<Claim>> GetClaims()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, _user.UserName)
            };

            var roles = await _userManager.GetRolesAsync(_user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            return claims;
        }

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings").Get<JwtSettings>();

            var tokenOptions = new JwtSecurityToken
            (
                issuer: jwtSettings.Issuer,
                audience: jwtSettings.Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings.AccessExpiration)),
                signingCredentials: signingCredentials
            );

            return tokenOptions;
        }
    }
}
