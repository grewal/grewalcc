/*  Copyright 2021 Grewal Inc.  All Rights Reserved.
    Author:  Yadwinder Grewal (ygrewal@gmail.com)
*/

#include <stdio.h>
#include "fcgio.h"
#include "../security/security.h"

using namespace std;

int main(int argc, char *argv[]) {

    /* Backup the stdio streambufs */
    streambuf * cin_streambuf  = cin.rdbuf();
    streambuf * cout_streambuf = cout.rdbuf();
    streambuf * cerr_streambuf = cerr.rdbuf();

    /* Initialize fast-cgi */
    FCGX_Request request;
    FCGX_Init();
    FCGX_InitRequest(&request, 0, 0);

    /* Process the incoming http_request */
    while (FCGX_Accept_r(&request) == 0) {
        fcgi_streambuf cin_fcgi_streambuf(request.in);
        fcgi_streambuf cout_fcgi_streambuf(request.out);
        fcgi_streambuf cerr_fcgi_streambuf(request.err);
        cin.rdbuf(&cin_fcgi_streambuf);
        cout.rdbuf(&cout_fcgi_streambuf);
        cerr.rdbuf(&cerr_fcgi_streambuf);

        fcgi_ostream  fcgi;
        char* request_uri_ = FCGX_GetParam("REQUEST_URI", request.envp);
        char* remote_ip_ = FCGX_GetParam("REMOTE_ADDR", request.envp);
        char* user_agent_ = FCGX_GetParam("HTTP_USER_AGENT", request.envp);
        char* http_host_ = FCGX_GetParam("HTTP_HOST", request.envp);

        grewal::Security* security_ = new grewal::Security();

        // check for robots.txt
        if (security_ -> isRobotsTxt(request_uri_)) {
            std::cout << "Content-type: text/plain\r\n\r\n" << std::endl;
            std::cout << "User-agent: *\nAllow: /" << std::endl;
        }

        else {  // ***** HOMEPAGE AND ALL ELSE *****

            /* Homepage */
            std::cout << "Content-type: text/html\r\n\r\n" << std::endl;
            std::cout << "<meta name='viewport' content='width=device-width, initial-scale=1.0/'>";
            //std::cout << "<head><link rel='shortcut icon' href='https://sites.google.com/site/ygrewal/favico.gif' type='image/x-icon />";
            std::cout << "<title>" << http_host_ << "</title></head>"
                      << "<body><center>Grewal.cc";
            if (security_->isInternal(remote_ip_)) {
                std::cout << "<br><br><font color='red'>INTERNAL</font><br><br>";
            }
            std::cout << "<br><br><br><br><br><b>IP: </b>" << remote_ip_
                      << "<br><br><b>user-agent: </b>" << user_agent_
                      << "<br><br><b>sub-domain: </b>" << security_->getSubDomain(http_host_);
            std::cout << "</center></body></html>" << std::endl;
            delete security_;

        }  // end HOMEPAGE

        // the fcgi_streambuf destructor will auto flush
    } // end while (FCGX_Accept_r(&request) == 0)

    /* restore stdio streambufs */
    cin.rdbuf(cin_streambuf);
    cout.rdbuf(cout_streambuf);
    cerr.rdbuf(cerr_streambuf);

    return 0;
} // end main
