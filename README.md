# 大学成绩自动监控系统

基于 GitHub Actions 的免费成绩监控工具，支持新疆农业大学教务系统。当有成绩更新时会自动发送微信通知。

## 功能特点

- 完全免费：基于 GitHub Actions，无需服务器费用
- 自动监控：定时检查教务系统成绩更新
- 微信通知：成绩变化时即时推送到微信
- 数据安全：所有敏感信息通过 GitHub Secrets 加密存储
- 智能对比：只通知真正的成绩变化，避免重复提醒

## 快速开始

### 第一步：Fork 这个仓库

点击页面右上角的 **Fork** 按钮，将仓库复制到你的账户下。

### 第二步：准备微信机器人

1. 在微信中创建群聊（可以只有你一个人）
2. 添加企业微信机器人：群聊右上角 → 群管理 → 群机器人 → 添加
3. 选择"企业微信"类型，复制生成的 Webhook URL

### 第三步：设置数据存储

#### 创建 GitHub Token：
1. 点击你的头像 → Settings → Developer settings
2. Personal access tokens → Tokens (classic)
3. Generate new token (classic)，勾选 `gist` 权限
4. 复制并保存 token

#### 创建私有 Gist：
1. 访问 https://gist.github.com
2. 文件名：`grades_data.json`，内容：`{}`
3. 选择 Create secret gist
4. 复制 URL 中的 Gist ID

### 第四步：配置 Secrets

在你 Fork 的仓库中：Settings → Secrets and variables → Actions

添加以下配置：

| Secret 名称 | 值 | 说明 |
|------------|----|----|
| `STUDENT_USERNAME` | 你的学号 | 教务系统用户名 |
| `STUDENT_PASSWORD` | 你的密码 | 教务系统密码 |
| `WECHAT_WEBHOOK` | 微信机器人URL | 微信通知地址 |
| `GITHUB_TOKEN` | GitHub Token | 访问 Gist 权限 |
| `GIST_ID` | Gist ID | 数据存储位置 |

### 第五步：启动监控

1. 点击 Actions 标签
2. 启用 Workflows
3. 点击 Grade Monitor → Run workflow 测试运行

## 自定义配置

### 修改检查频率

编辑 `.github/workflows/grade_monitor.yml` 中的 cron 表达式：

```yaml
# 每小时检查
- cron: '0 * * * *'

# 每天 8:00 和 18:00 检查
- cron: '0 8,18 * * *'

# 工作日 10:00 检查
- cron: '0 10 * * 1-5'

