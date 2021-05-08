// Author: Yadwinder Grewal
// Copyright 2021 Grewal.cc

#include "re2/re2.h"
#include "security.h"

namespace grewal {
  Security::Security() {}

  bool Security::isInternal(const char *ipToCheck_) const {
    return re2::RE2::PartialMatch(ipToCheck_, "76.102.1.99");
  }

  bool Security::isRobotsTxt(const char *url_) const {
    return re2::RE2::PartialMatch(url_, "robots.txt"); 
  }

  const char* Security::getSubDomain(const char* host_) {
    const char* value = "";
    if (re2::RE2::PartialMatch(host_, "^w")) {
      value = "www";
    } else if (re2::RE2::PartialMatch(host_, "^y")) {
      value = "yadwinder";
    } else if (re2::RE2::FullMatch(host_, "m.grewal.cc")) {
      value = "m";
    } else if (re2::RE2::PartialMatch(host_, "^r")) {
      value = "raman";
    }
    return value;
  } // end getSubDomain

} // namespace grewal 
