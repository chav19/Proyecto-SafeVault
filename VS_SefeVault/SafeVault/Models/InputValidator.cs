using System;
using System.Text.RegularExpressions;
using System.Web;

public class InputValidator {
    // Permite solo letras, números y guiones bajos (evita caracteres especiales de XSS)
    private static readonly Regex UsernameRegex = new Regex(@"^[a-zA-Z0-9_]{3,30}$");
    
    // Formato estándar de email seguro
    private static readonly Regex EmailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");

    public static bool ValidateAndSanitize(string username, string email, out string sanitizedUsername, out string sanitizedEmail) {
        sanitizedUsername = string.Empty;
        sanitizedEmail = string.Empty;

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(email)) {
            return false;
        }

        // 1. Validar estructuras con Expresiones Regulares
        if (!UsernameRegex.IsMatch(username) || !EmailRegex.IsMatch(email)) {
            return false;
        }

        // 2. Sanitizar codificando entidades HTML (Mitigación Defensiva XSS)
        sanitizedUsername = HttpUtility.HtmlEncode(username.Trim());
        sanitizedEmail = HttpUtility.HtmlEncode(email.Trim().ToLower());

        return true;
    }
}