#ifndef MYSQL_UTIL_H_
#define MYSQL_UTIL_H_

#include <string>

namespace grewal {
namespace db {

class MySQLUtil {
public:
    MySQLUtil(const std::string& host, const std::string& user,
              const std::string& password, const std::string& database);
    ~MySQLUtil();

    bool logWebTraffic(const std::string& userAgent, const std::string& ip,
                       const std::string& time);

private:
    MYSQL* connection_;
    std::string host_;
    std::string user_;
    std::string password_;
    std::string database_;
};

} // namespace db
} // namespace grewal

#endif // MYSQL_UTIL_H_
