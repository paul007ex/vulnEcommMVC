using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();

builder.WebHost.ConfigureKestrel(opts =>
{
    // Insecure HTTP endpoint
    opts.ListenLocalhost(8080);
    // Secure HTTPS endpoint (dev certificate)
    opts.ListenLocalhost(8443, listenOpts => listenOpts.UseHttps());
});

var app = builder.Build();

// Optionally redirect HTTP → HTTPS globally
app.UseHttpsRedirection();

app.UseRouting();
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");
});

app.Run();
