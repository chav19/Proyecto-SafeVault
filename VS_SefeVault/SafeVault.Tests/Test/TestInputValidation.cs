// Tests/TestInputValidation.cs
using SafeVault;
using SafeVault.Models; // Agregado para que reconozca el repositorio
using NUnit.Framework;

[TestFixture]
public class TestInputValidation {

    [Test]
    public void TestForSQLInjection() {
        // Arrange: Intentos comunes de saltarse la BD mediante inyección SQL
        string maliciousUsername = "admin' OR '1'='1";
        string maliciousEmail = "test@safevault.com; DROP TABLE Users;";

        // Act: Enviar los datos maliciosos a nuestro validador
        bool isValid = InputValidator.ValidateAndSanitize(maliciousUsername, maliciousEmail, out _, out _);

        // Assert: Sintaxis corregida para NUnit moderno
        Assert.That(isValid, Is.False, "El sistema falló al bloquear un intento de SQL Injection.");
    }

    [Test]
    public void TestForXSS() {
        // Arrange: Scripts maliciosos diseñados para ejecutarse en el navegador
        string xssUsername = "<script>alert('XSS')</script>";
        string validEmail = "user@safevault.com";

        // Act: Validar los campos
        bool isValid = InputValidator.ValidateAndSanitize(xssUsername, validEmail, out string sanitizedUser, out _);

        // Assert: Sintaxis corregida para NUnit moderno
        Assert.That(!isValid || sanitizedUser.Contains("&lt;script&gt;"), Is.True, 
            "El sistema permitió un script malicioso XSS sin sanitizar.");
    }

    [Test]
    public void Test_DebuggedSearch_BlocksSQLInjection() {
        // Arrange: Un atacante intenta inyectar código SQL destructivo en la barra de búsqueda
        UserRepository repository = new UserRepository();
        string sqlAttackInput = "admin' OR 1=1; DROP TABLE Users;--";

        // Act: Ejecutar la búsqueda depurada
        bool result = repository.LegacySearchDebugged(sqlAttackInput, out string message);

        // Assert: El sistema procesa la cadena como un texto literal y no ejecuta el SQL malicioso
        Assert.That(result, Is.False);
        Assert.That(message, Does.Not.Contain("Error interno"), "La consulta falló a nivel de base de datos debido a sintaxis rota.");
    }

    [Test]
    public void Test_DebuggedSearch_EscapesXSSPayload() {
        // Arrange: Un atacante ingresa código HTML/JS reflejado
        UserRepository repository = new UserRepository();
        string xssAttackInput = "<script>stealCookies()</script>";

        // Act: Intentar buscar y obtener el mensaje de respuesta reflejado
        repository.LegacySearchDebugged(xssAttackInput, out string message);

        // Assert: El payload malicioso debe estar sanitizado y codificado (HtmlEncoded)
        Assert.That(message, Does.Not.Contain("<script>"), "¡Vulnerabilidad Crítica! El script XSS se reflejó en texto plano.");
        Assert.That(message, Does.Contain("&lt;script&gt;"), "El sistema no codificó adecuadamente los caracteres peligrosos.");
    }
}