#include <stdio.h>
#include "fcgio.h"
#include "../security/security.h"
#include <ctemplate/template.h>

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
        if (security_->isRobotsTxt(request_uri_)) {
            std::cout << "Content-type: text/plain\r\n\r\n" << std::endl;
            std::cout << "User-agent: *\nAllow: /" << std::endl;
        }

        else {  // ***** HOMEPAGE AND ALL ELSE *****

            /* Homepage */
            ctemplate::TemplateDictionary dict("home_general");
            dict.SetValue("HTTP_HOST", http_host_);
            dict.SetValue("REMOTE_IP", remote_ip_);
            dict.SetValue("USER_AGENT", user_agent_);
            dict.SetValue("SUB_DOMAIN", security_->getSubDomain(http_host_));

            if (security_->isInternal(remote_ip_)) {
                dict.ShowSection("INTERNAL");
            }

            std::string output;
            ctemplate::ExpandTemplate("templates/home_general.tpl", ctemplate::DO_NOT_STRIP, &dict, &output);

            std::cout << "Content-type: text/html\r\n\r\n" << output;

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
