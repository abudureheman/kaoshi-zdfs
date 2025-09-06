import os
import sys
import json
import requests
import time
import certifi
import random
import base64
import re
from datetime import datetime
from Crypto.Util import number
from pyquery import PyQuery as pq
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from urllib3.util.ssl_ import create_urllib3_context

# 自定义适配器类
class CipherSuiteAdapter(HTTPAdapter):
    def __init__(self, ciphers, **kwargs):
        self.ciphers = ciphers
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        context = create_urllib3_context(ciphers=self.ciphers)
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=context
        )

# 创建全局session
global_session = requests.Session()
global_session.mount("https://", CipherSuiteAdapter(
    "ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH"
))

# [这里包含你之前所有的登录和查询函数，保持原样]
# 为节省空间，我省略了重复的函数定义

def save_to_github_gist(data, gist_id, token):
    """保存数据到GitHub Gist作为持久化存储"""
    if not gist_id or not token:
        print("未配置GitHub Gist，跳过数据保存")
        return False
        
    url = f"https://api.github.com/gists/{gist_id}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    payload = {
        "files": {
            "grades_data.json": {
                "content": json.dumps(data, ensure_ascii=False, indent=2)
            }
        }
    }
    
    try:
        response = requests.patch(url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            print("数据已保存到GitHub Gist")
            return True
        else:
            print(f"保存到Gist失败，状态码：{response.status_code}")
            return False
    except Exception as e:
        print(f"保存到Gist时出错：{e}")
        return False

def load_from_github_gist(gist_id, token):
    """从GitHub Gist加载历史数据"""
    if not gist_id or not token:
        print("未配置GitHub Gist，无法加载历史数据")
        return None
        
    url = f"https://api.github.com/gists/{gist_id}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            gist_data = response.json()
            if "grades_data.json" in gist_data["files"]:
                content = gist_data["files"]["grades_data.json"]["content"]
                return json.loads(content)
        else:
            print(f"从Gist加载数据失败，状态码：{response.status_code}")
    except Exception as e:
        print(f"从Gist加载数据时出错：{e}")
    
    return None

def github_actions_main():
    """GitHub Actions专用的主函数"""
    print(f"开始成绩监控 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 从环境变量获取配置
    username = os.environ.get('STUDENT_USERNAME')
    password = os.environ.get('STUDENT_PASSWORD')
    webhook_url = os.environ.get('WECHAT_WEBHOOK')
    github_token = os.environ.get('GITHUB_TOKEN')
    gist_id = os.environ.get('GIST_ID')
    
    if not username or not password:
        print("错误：未设置学生用户名或密码")
        sys.exit(1)
    
    try:
        # 1. 直接登录（不使用本地cookie文件）
        print("正在登录教务系统...")
        login_result = jwxt_login(username, password)
        
        if login_result.get("code") != 1000:
            print(f"登录失败：{login_result.get('msg', '未知错误')}")
            sys.exit(1)
        
        print("登录成功")
        
        # 2. 获取最新成绩
        print("正在获取成绩数据...")
        result = kecheng()
        
        if result.get("code") != 200:
            print(f"成绩查询失败：{result.get('msg', '未知错误')}")
            sys.exit(1)
        
        new_grades = result.get("data")
        course_count = len(new_grades.get("items", []))
        print(f"成功获取 {course_count} 门课程的成绩")
        
        # 3. 加载历史数据进行比较
        old_grades_data = load_from_github_gist(gist_id, github_token)
        
        # 4. 比较成绩变化
        changes = compare_grades(old_grades_data, new_grades)
        print(f"成绩对比完成：新增 {len(changes['new_courses'])} 门，更新 {len(changes['updated_scores'])} 门")
        
        # 5. 发送通知
        if changes["total_changes"] > 0:
            message = format_grade_change_message(changes)
            if message and webhook_url:
                if send_wechat_notification(message, webhook_url):
                    print("成绩变化通知已发送")
                else:
                    print("通知发送失败")
            else:
                print("检测到成绩变化但未配置微信通知")
                # 在GitHub Actions日志中显示变化
                print("变化详情：")
                print(message)
        else:
            print("成绩无变化")
        
        # 6. 保存最新数据
        save_data = {
            "timestamp": datetime.now().isoformat(),
            "grades": new_grades,
            "total_courses": course_count
        }
        save_to_github_gist(save_data, gist_id, github_token)
        
        print("成绩监控完成")
        
    except Exception as e:
        print(f"执行过程中出错：{e}")
        sys.exit(1)

if __name__ == "__main__":
    github_actions_main()
