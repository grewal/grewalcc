// Copyright 2024 Grewal Inc. All Rights Reserved.
// Author: Yadwinder Grewal (ygrewal@gmail.com)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>
#include <iostream>
#include "fcgio.h"
#include "mariadb/mysql.h"
#include "../security/sanitizer.h"
#include "../security/security.h"

MYSQL* initializeMySQL();
bool setHttpRequestLog(MYSQL* mysql, const FCGX_Request& request);
FCGX_Request initializeFCGXRequest();

int main(int argc, char *argv[]) {
    // Backup the stdio streambufs
    std::streambuf *cin_streambuf = std::cin.rdbuf();
    std::streambuf *cout_streambuf = std::cout.rdbuf();
    std::streambuf *cerr_streambuf = std::cerr.rdbuf();

    // Initialize fast-cgi
    FCGX_Request request;
    FCGX_Init();
    FCGX_InitRequest(&request, 0, 0);

    // Process the incoming http_request
    while (FCGX_Accept_r(&request) == 0) {
        fcgi_streambuf cin_fcgi_streambuf(request.in);
        fcgi_streambuf cout_fcgi_streambuf(request.out);
        fcgi_streambuf cerr_fcgi_streambuf(request.err);
        std::cin.rdbuf(&cin_fcgi_streambuf);
        std::cout.rdbuf(&cout_fcgi_streambuf);
        std::cerr.rdbuf(&cerr_fcgi_streambuf);

        // Extract HTTP request parameters
        const char* accept_ = FCGX_GetParam("HTTP_ACCEPT", request.envp);
        const char* accept_encoding_ = FCGX_GetParam("HTTP_ACCEPT_ENCODING", request.envp);
        const char* accept_language_ = FCGX_GetParam("HTTP_ACCEPT_LANGUAGE", request.envp);
        const char* connection_ = FCGX_GetParam("HTTP_CONNECTION", request.envp);
        const char* content_length_ = FCGX_GetParam("CONTENT_LENGTH", request.envp);
        const char* content_type_ = FCGX_GetParam("CONTENT_TYPE", request.envp);
        const char* cookie_ = FCGX_GetParam("HTTP_COOKIE", request.envp);
        const char* document_uri_ = FCGX_GetParam("DOCUMENT_URI", request.envp);
        const char* http_host_ = FCGX_GetParam("HTTP_HOST", request.envp);
        const char* http_method_ = FCGX_GetParam("REQUEST_METHOD", request.envp); // Alias for request_method
        const char* protocol_ = FCGX_GetParam("SERVER_PROTOCOL", request.envp); // Alias for server_protocol
        const char* query_string_ = FCGX_GetParam("QUERY_STRING", request.envp);
        const char* referer_ = FCGX_GetParam("HTTP_REFERER", request.envp);
        const char* remote_addr_ = FCGX_GetParam("REMOTE_ADDR", request.envp);
        const char* remote_port_ = FCGX_GetParam("REMOTE_PORT", request.envp);
        const char* request_method_ = FCGX_GetParam("REQUEST_METHOD", request.envp);
        const char* request_uri_ = FCGX_GetParam("REQUEST_URI", request.envp);
        const char* server_addr_ = FCGX_GetParam("SERVER_ADDR", request.envp);
        const char* server_port_ = FCGX_GetParam("SERVER_PORT", request.envp);
        const char* user_agent_ = FCGX_GetParam("HTTP_USER_AGENT", request.envp);

        const char* ip_address_ = remote_addr_;
        const char* port_ = remote_port_;
        const char* hostname_ = http_host_;
        const char* http_method_alias_ = request_method_;
        const char* uri_ = document_uri_;
        const char* protocol_alias_ = protocol_;

        grewal::Sanitizer* sanitizer_ = new grewal::Sanitizer();
        std::map<std::string, std::string> httpPostParametersMap;
        std::string content = sanitizer_->getRequestContent(request);
        httpPostParametersMap = sanitizer_->getContentVariablesMap(content);
        grewal::fcgi_param fcgi_ = sanitizer_->getFCGIParameters(request);
        delete sanitizer_;

        grewal::Security* security_ = new grewal::Security();

        // check for robots.txt
        if (security_->isRobotsTxt(request_uri_)) {
            std::cout << "Content-type: text/plain\r\n\r\n" << std::endl;
            std::cout << "User-agent: *\nAllow: /" << std::endl;
        } else { // ***** HOMEPAGE AND ALL ELSE *****

            /* Homepage */
            std::cout << "Content-type: text/html\r\n\r\n" << std::endl;
            std::cout << "<meta name='viewport' content='width=device-width, initial-scale=1.0/'>";
            std::cout << "<title>" << http_host_ << "</title></head>"
                << "<body><center>Grewal.cc";
            if (security_->isInternal(remote_port_)) {
                std::cout << "<br><br><font color='red'>INTERNAL</font><br><br>";
            }
            std::cout << "<br><br><br><br><br><b>IP: </b>" << remote_addr_
                << "<br><br><b>user-agent: </b>" << user_agent_
                << "<br><br><b>server protocol</b>: " << protocol_
                << "<br><br><b>sub-domain: </b>: " << http_host_ << std::endl;


	    // Write the http request logs to mariadb
            MYSQL* mysql_ = initializeMySQL();
            bool writeSuccess = setHttpRequestLog(mysql_, request);
            std::cout << (writeSuccess ? "<br>SUCCESS" : "<br>FAILURE") << std::endl;

            mysql_close(mysql_);
            std::cout << "</center></body></html>" << std::endl;
        }
    }
}

FCGX_Request initializeFCGXRequest() {
    FCGX_Request request;
    FCGX_InitRequest(&request, 0, 0);
    return request;
}

MYSQL* initializeMySQL() {
    MYSQL* mysql = mysql_init(nullptr);
    if (!mysql) {
        std::cout << "Error: Failed to initialize MySQL" << std::endl;
        return nullptr;
    }

    if (!mysql_real_connect(mysql, "localhost", "http_writer", "grewal_http_write_logs_password", "grewal", 0, nullptr, 0)) {
        std::cout << "Error: Failed to connect to database: " << std::endl;
        mysql_close(mysql);
        return nullptr;
    }
    return mysql;
}

/*
 * Preconditions:
 * 	MySQL Connection: The function assumes that a valid connection to the MySQL database has been established prior to its invocation.
 * Postconditions:
 * 	HTTP Request Logging: After the function execution, the HTTP request details are logged into the specified MySQL database table.
 * 	Database Connection: The MySQL connection remains intact unless an error occurs during the logging process.

Summary:
The setHttpRequestLog function is responsible for logging HTTP request details into a MySQL database. 

-It takes the MySQL connection and the FastCGI request object as parameters. 
-The function constructs an SQL query based on various request parameters such as query string, request method, content type, user agent, etc. 
-Then, it executes the SQL query to insert the request details into the database table named http_request. 
-->If the logging process is successful, the function returns true; otherwise, it returns false. The function ensures that the provided MySQL connection is valid before proceeding with the logging operation. */

bool setHttpRequestLog(MYSQL* mysql_, const FCGX_Request& request) {
    if (!mysql_) {
        std::cout << "Error: Failed to initialize MySQL inside SETHTTP" << std::endl;
        return false;
    }

    // Extract HTTP request parameters
    const char* query_string_ = FCGX_GetParam("QUERY_STRING", request.envp) ? FCGX_GetParam("QUERY_STRING", request.envp) : "NO_QUERY_STRING";
    const char* request_method_ = FCGX_GetParam("REQUEST_METHOD", request.envp) ? FCGX_GetParam("REQUEST_METHOD", request.envp) : "NO_REQUEST_METHOD";
    const char* content_type_ = FCGX_GetParam("CONTENT_TYPE", request.envp) ? FCGX_GetParam("CONTENT_TYPE", request.envp) : "NO_CONTENT_TYPE";
    int content_length_ = FCGX_GetParam("CONTENT_LENGTH", request.envp) ? atoi(FCGX_GetParam("CONTENT_LENGTH", request.envp)) : 0;
    const char* request_uri_ = FCGX_GetParam("REQUEST_URI", request.envp) ? FCGX_GetParam("REQUEST_URI", request.envp) : "NO_REQUEST_URI";
    const char* document_uri_ = FCGX_GetParam("DOCUMENT_URI", request.envp) ? FCGX_GetParam("DOCUMENT_URI", request.envp) : "NO_DOCUMENT_URI";
    const char* server_protocol_ = FCGX_GetParam("SERVER_PROTOCOL", request.envp) ? FCGX_GetParam("SERVER_PROTOCOL", request.envp) : "NO_SERVER_PROTOCOL";
    const char* remote_addr_ = FCGX_GetParam("REMOTE_ADDR", request.envp) ? FCGX_GetParam("REMOTE_ADDR", request.envp) : "NO_REMOTE_ADDR";
    int remote_port_ = FCGX_GetParam("REMOTE_PORT", request.envp) ? atoi(FCGX_GetParam("REMOTE_PORT", request.envp)) : 0;
    const char* server_addr_ = FCGX_GetParam("SERVER_ADDR", request.envp) ? FCGX_GetParam("SERVER_ADDR", request.envp) : "NO_SERVER_ADDR";
    int server_port_ = FCGX_GetParam("SERVER_PORT", request.envp) ? atoi(FCGX_GetParam("SERVER_PORT", request.envp)) : 0;
    const char* user_agent_ = FCGX_GetParam("HTTP_USER_AGENT", request.envp) ? FCGX_GetParam("HTTP_USER_AGENT", request.envp) : "NO_HTTP_USER_AGENT";
    const char* referer_ = FCGX_GetParam("HTTP_REFERER", request.envp) ? FCGX_GetParam("HTTP_REFERER", request.envp) : "NO_HTTP_REFERER";
    const char* accept_ = FCGX_GetParam("HTTP_ACCEPT", request.envp) ? FCGX_GetParam("HTTP_ACCEPT", request.envp) : "NO_HTTP_ACCEPT";
    const char* accept_language_ = FCGX_GetParam("HTTP_ACCEPT_LANGUAGE", request.envp) ? FCGX_GetParam("HTTP_ACCEPT_LANGUAGE", request.envp) : "NO_HTTP_ACCEPT_LANGUAGE";
    const char* accept_encoding_ = FCGX_GetParam("HTTP_ACCEPT_ENCODING", request.envp) ? FCGX_GetParam("HTTP_ACCEPT_ENCODING", request.envp) : "NO_HTTP_ACCEPT_ENCODING";
    const char* cookie_ = FCGX_GetParam("HTTP_COOKIE", request.envp) ? FCGX_GetParam("HTTP_COOKIE", request.envp) : "NO_HTTP_COOKIE";
    const char* connection_ = FCGX_GetParam("HTTP_CONNECTION", request.envp) ? FCGX_GetParam("HTTP_CONNECTION", request.envp) : "NO_HTTP_CONNECTION";
    const char* ip_address_ = remote_addr_;
    int port_ = remote_port_;
    const char* hostname_ = FCGX_GetParam("HTTP_HOST", request.envp) ? FCGX_GetParam("HTTP_HOST", request.envp) : "NO_HTTP_HOST";
    const char* http_method_ = request_method_;
    const char* uri_ = document_uri_;
    const char* protocol_ = server_protocol_;

    // Construct the SQL query
    std::string query = "INSERT INTO http_request (query_string, request_method, content_type, content_length, request_uri, document_uri, server_protocol, remote_addr, remote_port, server_addr, server_port, user_agent, referer, accept, accept_language, accept_encoding, cookie, connection, ip_address, port, hostname, geolocation, http_method, uri, protocol, query_params, form_data, session_id, timestamp, raw_data) VALUES ('";
    query += query_string_;
    query += "', '";
    query += request_method_;
    query += "', '";
    query += content_type_;
    query += "', ";
    query += std::to_string(content_length_);
    query += ", '";
    query += request_uri_;
    query += "', '";
    query += document_uri_;
    query += "', '";
    query += server_protocol_;
    query += "', '";
    query += remote_addr_;
    query += "', ";
    query += std::to_string(remote_port_);
    query += ", '";
    query += server_addr_;
    query += "', ";
    query += std::to_string(server_port_);
    query += ", '";
    query += user_agent_;
    query += "', '";
    query += referer_;
    query += "', '";
    query += accept_;
    query += "', '";
    query += accept_language_;
    query += "', '";
    query += accept_encoding_;
    query += "', '";
    query += cookie_;
    query += "', '";
    query += connection_;
    query += "', '";
    query += ip_address_;
    query += "', ";
    query += std::to_string(port_);
    query += ", '";
    query += hostname_;
    query += "', NULL, '";
    query += http_method_;
    query += "', '";
    query += uri_;
    query += "', '";
    query += protocol_;
    query += "', NULL, NULL, NULL, CURRENT_TIMESTAMP, NULL);";

    // Execute the SQL query
    if (mysql_query(mysql_, query.c_str()) != 0) {
        std::cout << "Error: Failed to write the HTTP logs to MariaDB: " << mysql_error(mysql_) << std::endl;
        mysql_close(mysql_);
        return false;
    }

    mysql_close(mysql_);
    return true;
}
