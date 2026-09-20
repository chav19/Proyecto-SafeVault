// SafeVault.Tests/Tests/TestAuthSystem.cs
using NUnit.Framework;
using SafeVault.Models;

[TestFixture]
public class TestAuthSystem {
    private AuthService _authService;

    [SetUp]
    public void Setup() {
        _authService = new AuthService();
        // Registramos usuarios de prueba con diferentes roles
        _authService.RegisterUser("adminUser", "SecureAdminPass123!", "Admin");
        _authService.RegisterUser("normalUser", "StandardPass789!", "User");
    }

    [Test]
    public void TestLogin_WithValidCredentials_ReturnsTrueAndCorrectRole() {
        // Act: Intento de login exitoso
        bool loginResult = _authService.Login("adminUser", "SecureAdminPass123!", out string role);

        // Assert
        Assert.That(loginResult, Is.True);
        Assert.That(role, Is.EqualTo("Admin"));
    }

    [Test]
    public void TestLogin_WithInvalidPassword_ReturnsFalse() {
        // Act: Intento de login con contraseña incorrecta
        bool loginResult = _authService.Login("adminUser", "WrongPassword!", out _);

        // Assert
        Assert.That(loginResult, Is.False, "El sistema falló al permitir una contraseña incorrecta.");
    }

    [Test]
    public void TestAuthorization_AdminAccessingDashboard_ReturnsTrue() {
        // Act & Assert: Verificar que el rol Admin sí tiene permiso
        bool hasAccess = _authService.AccessAdminDashboard("Admin");
        Assert.That(hasAccess, Is.True);
    }

    [Test]
    public void TestAuthorization_UserAccessingDashboard_ReturnsFalse() {
        // Act & Assert: Verificar y simular un acceso no autorizado de un usuario común
        bool hasAccess = _authService.AccessAdminDashboard("User");
        Assert.That(hasAccess, Is.False, "¡Alerta de seguridad! Un usuario estándar logró acceder al panel de administración.");
    }
}
