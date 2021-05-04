// Author: Yadwinder Grewal
// Copyright: 2021 Grewal.cc

#ifndef GREWAL_SECURITY_H
#define GREWAL_SECURITY_H

namespace grewal {
  class Security {
    public:
      Security();

      // Checks if address matches internal IP range
      bool isInternal(const char*) const;
    };

} // namespace grewal 

#endif // GREWAL_SECURITY_H
