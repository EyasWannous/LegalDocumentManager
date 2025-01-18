using Ganss.Xss;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace LegalDocumentManager.Middelwares;

public class InputSanitizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HtmlSanitizer _sanitizer;

    public InputSanitizationMiddleware(RequestDelegate next)
    {
        _next = next;
        _sanitizer = new HtmlSanitizer();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Sanitize query string parameters
        if (context.Request.QueryString.HasValue)
        {
            var query = context.Request.Query;
            var sanitizedQuery = new Dictionary<string, string>();

            foreach (var key in query.Keys)
            {
                var value = query[key];
                if (value.IsNullOrEmpty())
                    continue;

                sanitizedQuery[key] = _sanitizer.Sanitize(value);
            }

            context.Request.Query = new QueryCollection(sanitizedQuery.ToDictionary(kvp => kvp.Key, kvp => new StringValues(kvp.Value)));
        }

        // Sanitize form data (if present)
        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            var sanitizedForm = new Dictionary<string, string>();

            foreach (var key in form.Keys)
            {
                var value = form[key];
                sanitizedForm[key] = _sanitizer.Sanitize(value);
            }

            context.Request.Form = new FormCollection(sanitizedForm.ToDictionary(kvp => kvp.Key, kvp => new StringValues(kvp.Value)));
        }

        // Sanitize JSON body (if present)
        if (context.Request.ContentType?.Contains("application/json") == true)
        {
            context.Request.EnableBuffering(); // Allow the request body to be read multiple times
            var originalBody = context.Request.Body;
            using (var reader = new StreamReader(originalBody))
            {
                var body = await reader.ReadToEndAsync();
                var sanitizedBody = _sanitizer.Sanitize(body);

                // Replace the request body with the sanitized content
                var sanitizedBodyBytes = System.Text.Encoding.UTF8.GetBytes(sanitizedBody);
                context.Request.Body = new MemoryStream(sanitizedBodyBytes);
            }
            context.Request.Body.Position = 0; // Reset the stream position for the next middleware
        }

        // Call the next middleware in the pipeline
        await _next(context);
    }
}
