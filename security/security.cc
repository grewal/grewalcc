// Author: Yadwinder Grewal
// Copyright 2021 Grewal.cc

#include "re2/re2.h"
#include "security.h"

namespace grewal {
  Security::Security() {}

  bool Security::isInternal(const char *ipToCheck_) const {
    return re2::RE2::PartialMatch(ipToCheck_, "76.102.1.99");
  }

} // namespace grewal 
