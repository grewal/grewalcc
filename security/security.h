// Author: Yadwinder Grewal
// Copyright: 2021 Grewal.cc

#ifndef GREWAL_SECURITY_H
#define GREWAL_SECURITY_H

namespace grewal {

class Security {

public:
    Security();

    // robots.txt
    bool isRobotsTxt(const char*) const;

    // Checks if address matches internal IP range
    bool isInternal(const char*) const;
    const char* getSubDomain(const char*);
};

} // namespace grewal

#endif // GREWAL_SECURITY_H
