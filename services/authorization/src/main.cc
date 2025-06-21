#include <iostream>
#include <string>
#include "absl/strings/str_cat.h"
#include <google/protobuf/message.h>

int main() {
    std::string message = absl::StrCat("Hello from Bazel using Abseil! ", "(Piece ", 1, ")");
    std::cout << message << std::endl;
    google::protobuf::Message *msg = nullptr;
    (void)msg;
    std::cout << "Linked against Protobuf!" << std::endl;
    return 0;
}
