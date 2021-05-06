//
// VirtualApp Native Project
//

#ifndef NDK_HELPER
#define NDK_HELPER

#include "VAJni.h"
#include <string>
class ScopeUtfString {
public:
    ScopeUtfString(jstring j_str);

    const char *c_str() {
        return _c_str;
    }

    std::string toString() {
        return std::string(_c_str);
    }

    ~ScopeUtfString();

private:
    jstring _j_str;
    const char *_c_str;
};


#endif //NDK_HELPER
