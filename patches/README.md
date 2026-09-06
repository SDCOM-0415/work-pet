# WorkDaddy 本地补丁

本目录保存对 [WorkDaddy](https://github.com/babygoton/WorkDaddy) 上游文件的本地修改，
覆盖到 `../WorkDaddy/scripts/` 对应文件即可生效：

| 文件 | 修改内容 |
|---|---|
| `daemon.js` | 启动即备份当前登录；WorkPet 单文件备份兼容；CodeBuddy 签到/账号能力 |
| `inject.js` | Trusted Types 兼容垫片（CodeBuddy/VS Code fork 安全策略） |
| `profiles.js` | codebuddy-cn profile 追踪自己的登录文件（Tencent-Cloud.coding-copilot.info），与 WorkBuddy 通道互相独立 |

更新上游后，重新应用本目录的三个文件即可恢复 CodeBuddy 集成能力。
