#include <stdio.h>
#include <stdlib.h>
#include "tests.h"

int main(int argc, char **argv) {
    const char *app_path = APP_PROCESS_64;
    // 32bit でテストする場合は下記を有効化
    // const char *app_path = APP_PROCESS_32;

    printf("===== app_process 多角的セキュリティ検証 =====\n");
    printf("ターゲット: %s\n", app_path);
    printf("セキュリティパッチレベル: 2022 (想定)\n\n");

    test_symlink_chown(app_path);
    test_env_overflow(app_path);
    test_argv_overflow(app_path);
    test_dl_hijack(app_path);
    test_toctou_race(app_path);

    printf("\nすべてのテストが完了しました。\n");
    return 0;
}
