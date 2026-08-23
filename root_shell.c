#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>

#define PORT "1234"
#define LOG_PATH "/sdcard/nc_launcher.log"
#define MAX_ATTEMPTS 3

// ============================================================
// ログ関数（タイムスタンプ＋追記）
// ============================================================
void log_append(const char *tag, const char *fmt, ...) {
    FILE *fp = fopen(LOG_PATH, "a");
    if (!fp) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(fp, "[%s] [%s] ", time_buf, tag);

    va_list args;
    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);

    fprintf(fp, "\n");
    fflush(fp);
    fclose(fp);
}

// ============================================================
// 手法の定義（各手法は argv 配列を返す）
// ============================================================
typedef struct {
    const char *name;
    char *const *argv;
} method_t;

// 手法1: toybox nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l
char *const method1_argv[] = {
    "toybox", "nc", "-s", "127.0.0.1", "-p", PORT, "-L", "/system/bin/sh", "-l", NULL
};

// 手法2: toybox nc -l -p 1234 -e /system/bin/sh (toybox は -e 非対応かもしれないが一応)
char *const method2_argv[] = {
    "toybox", "nc", "-l", "-p", PORT, "-e", "/system/bin/sh", NULL
};

// 手法3: sh -c "toybox nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l"
char *const method3_argv[] = {
    "sh", "-c", "toybox nc -s 127.0.0.1 -p " PORT " -L /system/bin/sh -l", NULL
};

// 手法4: nc (busybox 版など) で試す
char *const method4_argv[] = {
    "nc", "-s", "127.0.0.1", "-p", PORT, "-L", "/system/bin/sh", "-l", NULL
};

// 手法5: /system/bin/sh -c "toybox nc ..." (絶対パス)
char *const method5_argv[] = {
    "/system/bin/sh", "-c", "toybox nc -s 127.0.0.1 -p " PORT " -L /system/bin/sh -l", NULL
};

// 手法6: toybox nc -l -p 1234 -L /system/bin/sh -s 127.0.0.1 (順序入れ替え)
char *const method6_argv[] = {
    "toybox", "nc", "-l", "-p", PORT, "-L", "/system/bin/sh", "-s", "127.0.0.1", NULL
};

// 全手法のリスト
method_t methods[] = {
    { "toybox nc -s -p -L", method1_argv },
    { "toybox nc -l -p -e", method2_argv },
    { "sh -c \"toybox nc ...\"", method3_argv },
    { "nc -s -p -L (busybox)", method4_argv },
    { "/system/bin/sh -c \"toybox nc ...\"", method5_argv },
    { "toybox nc -l -p -L -s", method6_argv },
};
const int num_methods = sizeof(methods) / sizeof(methods[0]);

// ============================================================
// 各手法を試行（子プロセスで exec し、即死したら失敗と判定）
// ============================================================
int try_method(method_t *m, int *status_out) {
    pid_t pid = fork();
    if (pid < 0) {
        log_append("ERROR", "fork() failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        // 子プロセス: 手法を exec
        // シグナルリセット
        signal(SIGPIPE, SIG_DFL);
        // stdout/stderr を /dev/null にリダイレクト（エラーメッセージはログに記録しない）
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execvp(m->argv[0], m->argv);
        // exec 失敗
        fprintf(stderr, "execvp failed: %s\n", strerror(errno));
        exit(127);
    }

    // 親プロセス: 子の終了を監視（最大2秒待機）
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    if (result == 0) {
        // まだ動いている ＝ 成功（nc が待機状態）
        log_append("INFO", "Method '%s' succeeded (process %d running)", m->name, pid);
        *status_out = 0;
        return 1; // 成功
    } else if (result == pid) {
        // 子が終了した ＝ 失敗
        if (WIFEXITED(status)) {
            log_append("FAIL", "Method '%s' exited with code %d", m->name, WEXITSTATUS(status));
            *status_out = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            log_append("FAIL", "Method '%s' killed by signal %d", m->name, WTERMSIG(status));
            *status_out = -1;
        } else {
            log_append("FAIL", "Method '%s' terminated abnormally", m->name);
            *status_out = -1;
        }
        return 0; // 失敗
    } else {
        // waitpid エラー
        log_append("ERROR", "waitpid() failed: %s", strerror(errno));
        return -1;
    }
}

// ============================================================
// メイン（起動時に /system/bin/sh を port に待機させる）
// ============================================================
int main(int argc, char **argv) {
    int port = 1234;
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) port = 1234;
    }

    log_append("START", "=== nc_launcher starting (target port %d) ===", port);

    // 多重起動防止: ロックファイル（任意）
    // 今回は省略（必要に応じて実装）

    // 各手法を順に試行
    int success = 0;
    for (int i = 0; i < num_methods; i++) {
        log_append("INFO", "Trying method %d/%d: %s", i+1, num_methods, methods[i].name);
        int status;
        int result = try_method(&methods[i], &status);
        if (result == 1) {
            // 成功 → 子プロセスがバックグラウンドで動いているので、親は終了しても良い
            log_append("SUCCESS", "Method '%s' succeeded. Shell is listening on port %d", methods[i].name, port);
            // 子プロセスをデタッチするために親は終了
            // ただし、子プロセスはまだ動いているので、init に引き継がれる
            return 0;
        } else if (result == -1) {
            log_append("ERROR", "try_method returned -1, skipping remaining methods?");
            // ここで続行するか中断するか
            // とりあえず次の手法へ
            continue;
        }
        // 失敗なら次の手法へ
        sleep(1); // ポート解放待ち
    }

    // すべて失敗
    log_append("FATAL", "All %d methods failed. No shell listening.", num_methods);
    fprintf(stderr, "All methods failed. Check log: %s\n", LOG_PATH);
    return 1;
}
