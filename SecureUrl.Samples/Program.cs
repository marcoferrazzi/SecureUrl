using Microsoft.AspNetCore.StaticFiles;
using Scalar.AspNetCore;
using SecureUrl.Core;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSecureUrlProtector(builder.Configuration);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var contentTypes = new FileExtensionContentTypeProvider();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();
app.UseStaticFiles();


// Endpoint: CreateLink
app.MapPost("/links/{fileName}", (string fileName, IUrlProtector protector, ClaimsPrincipal user, HttpContext context) =>
{
    //string userId = GetUserId(user);

    // Generate a temporary token bound to the user's identity
    //string token = protector.Protect(fileName, TimeSpan.FromMinutes(30), context: userId);
    string token = protector.Protect(fileName, TimeSpan.FromMinutes(30));

    // Generate the download URL
    string? downloadUrl = $"{context.Request.Scheme}://{context.Request.Host}/download/{token}";

    return Results.Ok(new { url = downloadUrl });
})
.WithName("CreateLink")
.WithSummary("Generates a secure download link for a file");

// Endpoint: Download
app.MapGet("/download/{token}", (string token, IUrlProtector protector, IConfiguration configuration, IWebHostEnvironment env, ClaimsPrincipal user, HttpContext context) =>
{
    //string userId = GetUserId(user);

    //string? fileName = protector.Unprotect(token, context: userId);
    string? fileName = protector.Unprotect(token);
    if (fileName is null)
    {
        return Results.NotFound(); // Token scaduto, manomesso o non valido
    }

    string storagePath = configuration["Storage:Path"]
        ?? env.WebRootPath
        ?? Path.Combine(env.ContentRootPath, "wwwroot");

    // Protection against Path Traversal attacks
    string root = Path.GetFullPath(storagePath);
    string fullPath = Path.GetFullPath(Path.Combine(root, fileName));

    if (!fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)
        || !File.Exists(fullPath))
    {
        return Results.NotFound();
    }

    // Resolve Content-Type to support streaming (e.g., HTTP 206)
    if (!contentTypes.TryGetContentType(fullPath, out string? contentType))
    {
        contentType = "application/octet-stream";
    }

    // Set security headers
    context.Response.Headers.CacheControl = "private, no-store";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";

    // Return the physical file with range request support
    return Results.File(fullPath, contentType: contentType, enableRangeProcessing: true);
})
.WithName("Download")
.WithSummary("Downloads the file using a temporary access token");

app.Run();
