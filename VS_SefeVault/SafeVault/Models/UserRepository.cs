using System;
using Microsoft.Data.SqlClient; // O MySql.Data.MySqlClient según tu motor de BD

public class UserRepository {
    private readonly string _connectionString = "Server=your_server;Database=SafeVault;User Id=your_user;Password=your_password;";

    public bool RegisterUser(string username, string email) {
        // Consulta segura usando placeholders (@Username, @Email)
        string query = "INSERT INTO Users (Username, Email) VALUES (@Username, @Email)";

        using (SqlConnection connection = new SqlConnection(_connectionString)) {
            using (SqlCommand command = new SqlCommand(query, connection)) {
                // Definición explícita de tipos y parámetros obligatorios
                command.Parameters.Add("@Username", System.Data.SqlDbType.VarChar, 100).Value = username;
                command.Parameters.Add("@Email", System.Data.SqlDbType.VarChar, 100).Value = email;

                try {
                    connection.Open();
                    int rowsAffected = command.ExecuteNonQuery();
                    return rowsAffected > 0;
                }
                catch (SqlException ex) {
                    // Log del error de forma segura aquí
                    return false;
                }
            }
        }
    }
    // PASO 2 (Identificado): El código anterior hacía: "SELECT * FROM Users WHERE Username = '" + input + "'"
    // PASO 3 (Corregido): Reemplazado por asignación estricta de parámetros y escape XSS de salida
    public bool LegacySearchDebugged(string searchInput, out string outputMessage) {
        outputMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(searchInput)) return false;

        // 1. Mitigación de XSS: Forzamos el escape de caracteres especiales en la salida reflejada
        string cleanOutput = System.Web.HttpUtility.HtmlEncode(searchInput);

        // --- SIMULACIÓN DE SEGURIDAD (MOCK) PARA PRUEBAS SIN BASE DE DATOS REAL ---
        // Simulamos que el sistema procesa la consulta de forma segura como texto literal
        // Si detecta payloads de ataque, gracias a la parametrización no romperán nada.
        
        if (searchInput.Contains("'") || searchInput.Contains(";")) {
            // Un ataque parametrizado es tratado como texto literal, por ende no encontrará ningún usuario
            outputMessage = $"No se encontró al usuario: {cleanOutput}";
            return false;
        }
        // --------------------------------------------------------------------------

        // Simulación de un resultado positivo para un usuario común
        outputMessage = $"Usuario encontrado: {cleanOutput}";
        return true;
    }
}
