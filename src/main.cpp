//
// TBOX-SEC-DSN-CR-011: 最小入口。
// main() 仅构造并运行 SecApplication，不解析配置、不初始化日志、不注册信号、
// 不维护运行循环--全部由 hwyz::Application 编排。
//

#include "sec_application.h"

int main(int argc, char* argv[]) {
    tbox::sec::SecApplication app;
    return app.run(argc, argv);
}
