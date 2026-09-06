# Work Pet 🤖

**多 AI Agent 签到宠物** —— 一个常驻桌面的透明小宠物，自动为多个 AI 编程客户端完成每日签到、多账号管理与积分到期提醒。

全部功能基于 **CDP（Chrome DevTools Protocol）注入**实现——后台无头服务经 CDP 连接各 AI 客户端，完成自动签到、多账号管理与积分到期提醒，无需打开客户端本体。以后还会接入更多 AI 端。

## ✨ 功能

- **自动签到**：打开 Work Pet 即自动完成全部账号签到，无需打开客户端本体
- **多账号管理**：每个客户端的所有账号集中管理，一键切换（自动重启客户端并登录）
- **积分条**：按到期时间归类、长度与积分数量成正比，悬停查看到期日期与剩余天数
- **设备签到感知**：对按"设备"限额的签到自动轮换账号、按天公平分配
- **单文件备份/恢复**：三端全部账号打包为一个 `WorkPet-accounts-<时间戳>.json`，拷到其他电脑即可一键恢复
- **桌面宠物**：3D 机器人形象（眨眼/天线呼吸/浮动动画），可隐藏到托盘
- **主题**：深色/浅色一键切换，字号大小可调

## 🗂 目录结构

```
WorkPet/
├── WorkPet-accounts.json        # 唯一的账号库（三端所有账号，本地生成）
├── accounts/
│   └── WorkPet-accounts-<时间戳>.json   # 导出的备份快照（可拷到其他电脑）
├── daemon.js                    # WorkPet 后台服务（签到/账号/备份 API）
└── desktop-ui/                  # Tauri 2 + React 19 + shadcn/ui 桌面端
```

> 账号数据只保存在本地，`accounts/`、`WorkPet-accounts*.json`、`.api-token` 均已在 `.gitignore` 中排除，不会上传。

## 🔧 构建

前置：Node.js 20+、Rust（stable）、WebView2（Windows 10/11 自带）

```bash
npm install
npx tauri build        # 产物在 desktop-ui/src-tauri/target/release/
```

开发调试：

```bash
npm run dev
```

## 📦 备份与恢复

- **导出**：点击面板右上角 💾，在安装根目录生成 `WorkPet-accounts-<时间戳>.json`
- **恢复**：设置 → 账号备份/恢复 → 「从 JSON 文件恢复…」，选择备份文件即可
- 适合换机迁移：把 JSON 拷到新电脑，装好 Work Pet 后选择文件恢复，无需重新登录

## 📦 自包含安装

WorkBuddy / CodeBuddy 端的引擎已**内置**（`desktop-ui/src-tauri/vendor/wd/`），安装包自带全部依赖，
用户无需安装任何第三方程序——安装后打开 Work Pet 即可使用全部功能。

## ⚠️ 免责声明

本项目为个人效率工具，与 Trae / WorkBuddy / CodeBuddy 官方无关。签到接口参数来自公开客户端行为分析，仅供学习交流，请勿用于商业用途。使用本项目产生的任何后果由使用者自行承担。

## 📄 License

[MIT](./LICENSE)
