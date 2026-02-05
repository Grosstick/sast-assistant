/**
 * Vulnerable Java Application - For Testing SAST Assistant
 * 
 * This file contains intentionally vulnerable code for SQL injection and XSS.
 * DO NOT use this code in production!
 */

package com.example.vulnerable;

import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerableApp extends HttpServlet {

    // =========================================================================
    // SQL INJECTION VULNERABILITIES
    // =========================================================================

    /**
     * VULNERABLE: SQL injection via string concatenation.
     * 
     * An attacker could input: ' OR '1'='1' --
     * This would return all users instead of just one.
     */
    public User getUserUnsafe(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        // BAD: String concatenation with user input
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        if (rs.next()) {
            return new User(rs.getString("id"), rs.getString("name"));
        }
        return null;
    }

    /**
     * VULNERABLE: SQL injection in login authentication.
     * 
     * An attacker could bypass authentication with:
     * username: admin' --
     * password: anything
     */
    public boolean loginUnsafe(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        // BAD: String concatenation in authentication query
        String query = "SELECT * FROM users WHERE username = '" + username + 
                       "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        return rs.next();
    }

    /**
     * VULNERABLE: SQL injection via String.format().
     */
    public void deleteUserUnsafe(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        // BAD: String.format with user input
        String query = String.format("DELETE FROM users WHERE id = '%s'", userId);
        stmt.executeUpdate(query);
    }

    /**
     * VULNERABLE: SQL injection in search functionality.
     */
    public ResultSet searchProductsUnsafe(String searchTerm) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        // BAD: User input in LIKE clause
        String query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
        return stmt.executeQuery(query);
    }

    // SAFE ALTERNATIVES

    /**
     * SAFE: Using PreparedStatement with parameterized query.
     */
    public User getUserSafe(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        
        // GOOD: PreparedStatement with placeholder
        String query = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, userId);
        
        ResultSet rs = pstmt.executeQuery();
        
        if (rs.next()) {
            return new User(rs.getString("id"), rs.getString("name"));
        }
        return null;
    }

    /**
     * SAFE: Using PreparedStatement for authentication.
     */
    public boolean loginSafe(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        
        // GOOD: PreparedStatement for authentication
        String query = "SELECT * FROM users WHERE username = ? AND password = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, username);
        pstmt.setString(2, password);
        
        ResultSet rs = pstmt.executeQuery();
        return rs.next();
    }

    // =========================================================================
    // XSS (CROSS-SITE SCRIPTING) VULNERABILITIES
    // =========================================================================

    /**
     * VULNERABLE: Reflected XSS via unescaped user input.
     * 
     * An attacker could craft a URL like:
     * /greet?name=<script>alert('XSS')</script>
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        String name = request.getParameter("name");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // BAD: Directly embedding user input in HTML response
        out.println("<html><body>");
        out.println("<h1>Hello, " + name + "!</h1>");
        out.println("</body></html>");
    }

    /**
     * VULNERABLE: XSS in error message.
     */
    public void showErrorUnsafe(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String errorMsg = request.getParameter("error");
        
        PrintWriter out = response.getWriter();
        
        // BAD: User input in error display
        out.println("<div class='error'>Error: " + errorMsg + "</div>");
    }

    /**
     * VULNERABLE: XSS in search results page.
     */
    public void displaySearchResultsUnsafe(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String query = request.getParameter("q");
        
        PrintWriter out = response.getWriter();
        
        // BAD: Echoing search query without escaping
        out.println("<html><body>");
        out.println("<h2>Search results for: " + query + "</h2>");
        out.println("<p>No results found.</p>");
        out.println("</body></html>");
    }

    /**
     * VULNERABLE: XSS in multiple HTML contexts.
     */
    public void displayProfileUnsafe(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String username = request.getParameter("user");
        String bio = request.getParameter("bio");
        
        PrintWriter out = response.getWriter();
        
        // BAD: User input in multiple contexts (HTML content, attribute, JavaScript)
        out.println("<html>");
        out.println("<head><title>" + username + "'s Profile</title></head>");
        out.println("<body>");
        out.println("<h1>Welcome, " + username + "</h1>");
        out.println("<div class='bio'>" + bio + "</div>");
        out.println("<script>var user = '" + username + "';</script>");
        out.println("</body></html>");
    }

    // SAFE ALTERNATIVES

    /**
     * SAFE: Using OWASP Encoder for HTML escaping.
     */
    public void greetSafe(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String name = request.getParameter("name");
        
        // Import: org.owasp.encoder.Encode
        // GOOD: Using OWASP Encoder
        String safeName = org.owasp.encoder.Encode.forHtml(name);
        
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Hello, " + safeName + "!</h1>");
        out.println("</body></html>");
    }

    /**
     * SAFE: Context-aware encoding for different HTML contexts.
     */
    public void displayProfileSafe(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String username = request.getParameter("user");
        String bio = request.getParameter("bio");
        
        // GOOD: Context-appropriate encoding
        String htmlUsername = org.owasp.encoder.Encode.forHtml(username);
        String htmlBio = org.owasp.encoder.Encode.forHtml(bio);
        String jsUsername = org.owasp.encoder.Encode.forJavaScript(username);
        
        PrintWriter out = response.getWriter();
        out.println("<html>");
        out.println("<head><title>" + htmlUsername + "'s Profile</title></head>");
        out.println("<body>");
        out.println("<h1>Welcome, " + htmlUsername + "</h1>");
        out.println("<div class='bio'>" + htmlBio + "</div>");
        out.println("<script>var user = '" + jsUsername + "';</script>");
        out.println("</body></html>");
    }

    // Helper class
    static class User {
        String id;
        String name;
        
        User(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }
}
