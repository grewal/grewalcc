/*  Copyright 2020 Grewal Inc.  All Rights Reserved.
    Author:  Yadwinder Grewal (ygrewal@gmail.com)
*/

#include <stdio.h>
#include "fcgio.h"

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

      /* Homepage */
      std::cout << "Content-type: text/html\r\n\r\n" << std::endl;
      std::cout << "<meta name='viewport' content='width=device-width, initial-scale=1.0/'>"
                << "<html><title>Grewal.cc</title><body><center>Grewal.cc</center>"
                << "</body></html>" << std::endl;

    // the fcgi_streambuf destructor will auto flush
    } // end while (FCGX_Accept_r(&request) == 0)

    /* restore stdio streambufs */
    cin.rdbuf(cin_streambuf);
    cout.rdbuf(cout_streambuf);
    cerr.rdbuf(cerr_streambuf);

  return 0;
} // end main
