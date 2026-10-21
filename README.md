# codex-fast-minimal

适用于 Windows Store 版 Codex 的本地 Fast 最小补丁。只调整 Fast 按钮显示与请求前的登录类型检查，仍保留配置中的 `fast_mode` 要求。Python 标准库实现，无自动下载。

本项目不是 OpenAI 官方产品。MIT 许可证仅适用于本仓库原创工具代码，不适用于 Codex 程序。本仓库不提供 Codex 安装包、完整程序、证书或用户配置。

## 支持范围

- 支持原版 Store 包 **26.930.3930.0**、**26.1007.2314.0** 和 **26.1013.4894.0**，校验目标文件 SHA256 和两处精确匹配。其他版本、已修改版本会拒绝处理。
- 26.1007 和 26.1013 使用共享 service-tier access 对象。补丁只移除请求/UI 的 ChatGPT/PAT 登录类型限制，保留原 Fast/Ultrafast 转换器、独立限制、加载状态、缓存与 memo 依赖；不改模型、Power 或 Ultra 推理选项。
- 不修改模型列表、Power/Ultra、Chrome 插件、提示词、服务器或代理。
- 不能保证上游接受 Fast，也不能给账号增加权限。按钮出现、请求发送和上游采用相应服务等级是不同的验收项。
- 排队消息在主进程中还有登录检查，本补丁没有修改它，因此不保证排队消息使用 Fast。

## 依赖

Windows 10/11、Windows PowerShell 5.1、Python 3.9+、Windows SDK 中的 MakeAppx 和 SignTool。签名和安装需要同一 Windows 用户的管理员 PowerShell。

若本机执行策略阻止脚本，审查源码后可在下面命令的 `-NoProfile` 后加入 `-ExecutionPolicy Bypass`；它仅适用于此次 PowerShell 进程，不修改系统执行策略。

## 使用

在仓库根目录操作。输出目录必须是不存在的新目录，位于安装目录之外，建议也位于源码仓库之外。

1. 检查支持版本，不安装、不创建证书：

   ```powershell
   powershell.exe -NoProfile -File .\scripts\Build.ps1
   ```

2. 构建 Fast 包和原版内容恢复包，不关闭 Codex：

   ```powershell
   powershell.exe -NoProfile -File .\scripts\Build.ps1 -Build -Compress -OutputRoot E:\GeoCAD2_Sync\codex-fast-build -Workers 4
   ```

   若 `python` 不在 PATH，添加 `-Python C:\path\to\python.exe`。SDK 无法自动找到时添加 `-WindowsSdkBin "C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64"`。

   默认使用 MakeAppx `/nc` 不压缩，减少打包耗时，代价是更大的文件。若希望正式签名时读写更少，建议在准备阶段添加 `-Compress`：提前压缩会增加离线构建时间，正式安装无需重新打包。构建需要数 GB 空间，构建阶段会逐文件验证包和 ASAR。

3. 从开始菜单单独打开 **管理员 Windows PowerShell**，先只检查：

   ```powershell
   powershell.exe -NoProfile -File .\scripts\Install.ps1 -BuildDirectory E:\GeoCAD2_Sync\codex-fast-build -Workers 4
   ```

4. 正式安装（不能从 Codex 内置终端运行）：

   ```powershell
   powershell.exe -NoProfile -File .\scripts\Install.ps1 -BuildDirectory E:\GeoCAD2_Sync\codex-fast-build -Workers 4 -Install
   ```

   输入 `INSTALL FAST` 后才创建本地不可导出的代码签名证书，将公钥证书加入系统 `TrustedPeople`，不会加入 `Root`。两包签名和验证完成后，脚本显示 `Closing Codex now`，关闭当前会话中的 Codex 进程，然后原位更新。请先结束重要任务。脚本不卸载应用或清空数据。

5. 启动后查看 Fast 按钮，再用自己的账号验证请求和上游服务等级。注册成功或发送启动请求不等于功能验收成功。

## 恢复

保留整个构建输出目录。需要恢复原版程序内容时，从独立管理员 PowerShell 运行：

```powershell
powershell.exe -NoProfile -File .\scripts\Install.ps1 -BuildDirectory E:\GeoCAD2_Sync\codex-fast-build -Recover
```

输入 `RECOVER ORIGINAL` 后也会关闭 Codex。恢复包使用更高版本号和本地签名，**不能恢复原 Store 签名**。脚本拒绝未知版本和降级；Store 更新会覆盖补丁，更新后应重新检查支持范围。

修改启动器的 ASAR 完整性哈希会使其原文件签名失效，新的包签名用于覆盖本地包。备份重要本地数据后再安装；不要分发自己的证书私钥或用户数据。

## 验证与当前状态

构建使用 8 路文件复制、连续 ASAR 区间写入和只读内存映射比较。完整目录 SHA256 比较默认 4 路并行。MSIX 大包按顺序读取，后台并行核验全部 SHA256 数据块，同一次读取计算整包 SHA256 与所有未压缩条目的 CRC，避免机械盘上多包竞争及重复读盘。小型压缩 XML 保留解压/CRC/分块校验；大压缩条目和 ZIP64 自动回到通用验证器。签名前顺序复制两个包，同一遍读取计算源 SHA256，避免额外完整读盘；所有复制通过后，最多并行签名两个独立包。仍使用 Windows 签名验证，并对最终包重新做完整分块校验。

`-Workers 1` 可串行运行；`-Workers 4` 是默认值，范围 1–16。较高并发不保证更快，取决于磁盘和 CPU。签名包完成验证并保存记录后，同一构建、同一证书的安装重试或恢复可复用已签名包，省去重复复制和签名；每次仍重新验证 Windows 签名、全部数据块和整包 SHA256，文件变化会拒绝安装。不会缓存“上次通过”的结果代替当前文件校验。任何工作线程失败都会终止安装。构建输出 `build-timings.json`，安装输出 `install-timings.json`；首次签名另输出 `signing-timings.json`，分别记录复制/哈希和 SignTool 耗时。真实签名速度尚未实测。

安装器会在管理员进程中检查所有用户的较新注册/暂存包，并在关闭前再次检查版本；发现较新版本就拒绝安装旧构建，不做降级。

```powershell
python -m unittest discover -s tests -v
node tests/test_service_tier.cjs
```

核心修改器用合成 ASAR、启动器和 MSIX 测试，并在原版 26.930.3930.0 ASAR 上离线逐项验证。仅目标 JS 内容变化，保留 `$$` 标识符；原安装使用的早期工具曾把 `$$` 误替换为 `$`，本实现已避免该问题。目标 JS 通过 `node --check`。

旧版构建/安装流程已有实际安装验收记录，早期本地补丁的 Fast 也获得用户验证。本次新增的 26.1007/26.1013 适配、并行校验和签名复用流程已完成离线测试及真实包只读预检，**尚未完成新版脚本的实际签名、安装和恢复验收**。本机历史测速不能保证其他机器的耗时，实际签名速度尚未测量。详见 [26.1007 验证记录](VALIDATION-26.1007.md) 和 [26.1013 验证记录](VALIDATION-26.1013.md)。
