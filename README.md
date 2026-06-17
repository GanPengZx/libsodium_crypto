# libsodium_crypto

一个基于 libsodium 的 C 语言加密解密库，支持安全的密码派生和流式加密/解密。

## 特性

- **安全的密码派生**: 使用 Argon2id 算法，抵抗 GPU 破解和暴力破解。
- **流式加解密**: 支持处理大文件，内存占用低。
- **防时序攻击**: 内置恒定时间比较函数。
- **简单易用**: 提供极简的 C API 接口。

## 编译指南

### 前置依赖

确保你的系统已安装 `libsodium`。

- **Windows (MSYS2/MinGW)**:
bash
pacman -S mingw-w64-x86_64-libsodium
- **Linux (Ubuntu/Debian)**:
bash
sudo apt-get install libsodium-dev
- **macOS**:
bash
brew install libsodium
### 编译静态库

进入项目根目录，运行以下命令：
bash
生成对象文件
gcc -c src/libsodium_crypto.c -Iinclude -O2 -std=c99
生成静态库 (Windows)
ar rcs libsodium_crypto.lib libsodium_crypto.o
生成静态库 (Linux/macOS)
ar rcs libsodium_crypto.a libsodium_crypto.o
### 编译动态库 (DLL/Shared Object)
bash
Windows
gcc -shared -o libsodium_crypto.dll src/libsodium_crypto.c -Iinclude -O2 -std=c99 -lsodium
Linux
gcc -shared -o libsodium_crypto.so src/libsodium_crypto.c -Iinclude -O2 -std=c99 -lsodium
macOS
gcc -shared -o libsodium_crypto.dylib src/libsodium_crypto.c -Iinclude -O2 -std=c99 -lsodium
## 安装与使用

### 1. 下载预编译库

从 [Releases](https://github.com/GanPengZx/libsodium_crypto/releases) 下载适合你系统的库文件：
- Windows: `libsodium_crypto.dll` + `libsodium_crypto.lib`
- Linux: `libsodium_crypto.so`
- macOS: `libsodium_crypto.dylib`

### 2. 集成到你的项目

#### C/C++ 项目
include "libsodium_crypto.h"
int main() {
ls_crypto_init();
const char *password = "MyStr0ng!P@ssw0rd";
const char *secret = "机密数据";

uint8_t *ciphertext = NULL;
size_t ciphertext_len = 0;

// 加密
ls_crypto_encrypt(password, (const uint8_t*)secret, strlen(secret),
                 &ciphertext, &ciphertext_len, NULL);

// 解密
uint8_t *plaintext = NULL;
size_t plaintext_len = 0;
ls_crypto_decrypt(password, ciphertext, ciphertext_len,
                 &plaintext, &plaintext_len, NULL);

// 清理
ls_crypto_free(ciphertext);
ls_crypto_free(plaintext);
ls_crypto_cleanup();

return 0;
}
#### 编译链接
gcc your_app.c -o your_app.exe -Iinclude -L. -llibsodium_crypto
Linux
gcc your_app.c -o your_app -Iinclude -L. -lsodium_crypto
### 3. 动态加载 (LoadLibrary)
include <windows.h>
typedef int (__cdecl *LS_CRYPTO_INIT)(void);
int main() {
HMODULE hDll = LoadLibrary("libsodium_crypto.dll");
LS_CRYPTO_INIT init = (LS_CRYPTO_INIT)GetProcAddress(hDll, "ls_crypto_init");
init();
FreeLibrary(hDll);
return 0;
}
## API 文档

### 核心函数

| 函数 | 说明 |
|------|------|
| `ls_crypto_init()` | 初始化库 |
| `ls_crypto_cleanup()` | 清理资源 |
| `ls_crypto_encrypt()` | 加密数据 |
| `ls_crypto_decrypt()` | 解密数据 |
| `ls_crypto_free()` | 释放内存 |
| `ls_crypto_check_password_strength()` | 检查密码强度 |

### 配置结构
typedef struct {
size_t max_plaintext_size; // 最大明文大小（默认 10MB）
int min_password_length; // 最小密码长度（默认 12）
int argon_ops_limit; // Argon2 运算成本
int argon_mem_limit; // Argon2 内存成本（KB）
int decryption_delay_ms; // 解密失败延迟（防暴力破解）
} ls_crypto_config_t;
### 错误码
typedef enum {
LS_CRYPTO_SUCCESS = 0, // 成功
LS_CRYPTO_ERR_MEMORY = 1, // 内存不足
LS_CRYPTO_ERR_PASSWORD_WEAK = 2, // 密码强度不足
LS_CRYPTO_ERR_ENCRYPTION_FAILED = 3, // 加密失败
LS_CRYPTO_ERR_DECRYPTION_FAILED = 4 // 解密失败（密码错误或数据损坏）
} ls_crypto_error_t;
## 安全最佳实践

### ✅ 推荐做法

1. **使用强密码**
// 好密码示例
"MyUn1qu3!P@ssw0rd#2024"
// 避免
"password123" // ❌ 弱密码
2. **及时清理内存**
// 正确
ls_crypto_free(data);
// 错误
free(data); // ❌ 可能导致内存泄漏
3. **验证密码强度**
if (!ls_crypto_check_password_strength(password)) {
printf("请使用更强的密码！
");
return;
}
### ❌ 常见错误
// ❌ 错误1：硬编码密码
const char *password = "fixed_password";
// ❌ 错误2：忽略返回值
ls_crypto_encrypt(...); // 未检查返回值
// ❌ 错误3：使用 strlen 处理二进制数据
size_t len = strlen(binary_data); // 二进制数据可能包含 \0
## 性能基准

| 数据大小 | 加密时间 | 解密时间 |
|----------|----------|----------|
| 1 KB     | ~0.5 ms  | ~0.3 ms  |
| 1 MB     | ~15 ms   | ~12 ms   |
| 10 MB    | ~150 ms  | ~120 ms  |

*测试环境：Intel i7-10700K, 32GB RAM, Windows 10*

## 测试

运行内置测试套件：
编译测试
gcc -o test_lib tests/test_lib.c src/libsodium_crypto.c -Iinclude -lsodium -O2 -std=c99
运行测试
./test_lib
预期输出：
运行 libsodium_crypto 测试...
✓ 密码强度测试通过
✓ 加密解密测试通过
✓ 错误密码测试通过
所有测试通过！
## 贡献指南

欢迎贡献！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 开发环境设置
安装依赖
sudo apt-get install libsodium-dev cmake clang-format valgrind
运行内存检查
valgrind --leak-check=full ./test_lib
## 许可证

本项目采用 **MIT 许可证** - 详见 [LICENSE](LICENSE) 文件。

## 致谢

- [libsodium](https://doc.libsodium.org/) - 优秀的加密库
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - 密码哈希竞赛冠军
- [Daniel J. Bernstein](https://cr.yp.to/) - 密码学先驱

## 支持

- 📧 **邮箱**: your.email@example.com
- 🐛 **Bug 报告**: [GitHub Issues](https://github.com/yourusername/libsodium_crypto/issues)
- 💬 **讨论**: [GitHub Discussions](https://github.com/yourusername/libsodium_crypto/discussions)

---

<div align="center">

**⭐ 如果这个项目对你有帮助，请给它一个 Star！ ⭐**

Made with ❤️ and 🔒 by Security Engineers

</div>
