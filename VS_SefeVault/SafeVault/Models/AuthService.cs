// SafeVault/Models/AuthService.cs
using System;
using System.Collections.Generic;

namespace SafeVault.Models {
    public class UserAccount {
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty; // Ejemplo: "Admin", "User"
    }

    public class AuthService {
        // Simulación de base de datos en memoria para usuarios de SafeVault
        private readonly Dictionary<string, UserAccount> _usersDb = new();

        // PASO 2: Registro con Hash de Contraseña usando BCrypt de forma segura
        public bool RegisterUser(string username, string password, string role) {
            if (_usersDb.ContainsKey(username.ToLower())) return false;

            // Genera un hash seguro y único (incluye salt automático)
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

            _usersDb[username.ToLower()] = new UserAccount {
                Username = username,
                PasswordHash = hashedPassword,
                Role = role
            };
            return true;
        }

        // PASO 2: Verificación de Credenciales en el Login
        public bool Login(string username, string password, out string userRole) {
            userRole = string.Empty;
            
            if (!_usersDb.TryGetValue(username.ToLower(), out var account)) {
                return false; // Usuario no encontrado
            }

            // Compara la contraseña en texto plano contra el hash almacenado de forma segura
            if (BCrypt.Net.BCrypt.Verify(password, account.PasswordHash)) {
                userRole = account.Role;
                return true;
            }

            return false; // Contraseña incorrecta
        }

        // PASO 3: Control de Acceso basado en Roles (RBAC) para el Admin Dashboard
        public bool AccessAdminDashboard(string userRole) {
            // Restringe el acceso de forma estricta: solo el rol "Admin" puede entrar
            return string.Equals(userRole, "Admin", StringComparison.OrdinalIgnoreCase);
        }
    }
}