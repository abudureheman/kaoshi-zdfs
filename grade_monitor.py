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

def b64_to_hex(b64_str: str) -> str:
    """Base64 → 大写16进制"""
    return base64.b64decode(b64_str).hex().upper()

def hex_to_b64(hex_str: str) -> str:
    """16进制 → Base64"""
    return base64.b64encode(bytes.fromhex(hex_str)).decode("utf-8")

def pkcs1_pad2_js_compatible(text: str, n: int) -> bytes:
    """JavaScript兼容的PKCS#1填充（支持UTF-8）"""
    utf8_bytes = []
    for char in text:
        code = ord(char)
        if code < 128:
            utf8_bytes.append(code)
        elif code < 2048:
            utf8_bytes.extend([(code >> 6) | 192, (code & 63) | 128])
        else:
            utf8_bytes.extend([
                (code >> 12) | 224,
                ((code >> 6) & 63) | 128,
                (code & 63) | 128
            ])
    
    if n < len(utf8_bytes) + 11:
        raise ValueError("消息对于RSA来说太长")
    
    ba = [0] * n
    
    # 从后往前填充消息
    i = len(utf8_bytes) - 1
    pos = n - 1
    while i >= 0:
        ba[pos] = utf8_bytes[i]
        pos -= 1
        i -= 1
    
    ba[pos] = 0
    pos -= 1
    
    # 随机填充（非零）
    while pos > 1:
        ba[pos] = random.randint(1, 255)
        pos -= 1
    
    ba[1] = 2
    ba[0] = 0
    
    return bytes(ba)

def rsa_encrypt_js_compatible(plain_password: str, modulus_b64: str, exponent_b64: str) -> str:
    """完全兼容JavaScript的RSA加密"""
    modulus_hex = b64_to_hex(modulus_b64)
    exponent_hex = b64_to_hex(exponent_b64)
    
    n = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    
    key_size = (n.bit_length() + 7) // 8
    
    padded_bytes = pkcs1_pad2_js_compatible(plain_password, key_size)
    m = number.bytes_to_long(padded_bytes)
    c = pow(m, e, n)
    
    hex_result = hex(c)[2:].upper()
    if len(hex_result) % 2 != 0:
        hex_result = "0" + hex_result
    
    return hex_to_b64(hex_result)

def get_csrftoken():
    """从登录页获取csrftoken"""
    try:
        url = f"https://jwxt.xjau.edu.cn/jwglxt/xtgl/login_slogin.html?time={str(int(random.random() * 10**13))}"
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        response = global_session.get(url, headers=headers, timeout=10, verify=certifi.where())
        response.raise_for_status()
        
        csrftoken_match = re.search(r'name="csrftoken"\s+value="([^"]+)"', response.text)
        if not csrftoken_match:
            raise ValueError("未从登录页找到csrftoken")
        
        return csrftoken_match.group(1), response.text
        
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"请求登录页失败：{e}")

def get_rsa_key():
    """获取动态RSA密钥"""
    timestamp = str(int(random.random() * 10**13))
    key_url = f"https://jwxt.xjau.edu.cn/jwglxt/xtgl/login_getPublicKey.html?time={timestamp}"
    
    try:
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Origin": "https://jwxt.xjau.edu.cn",
            "Referer": "https://jwxt.xjau.edu.cn/jwglxt/xtgl/login_slogin.html",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        response = global_session.get(key_url, headers=headers, timeout=10, verify=certifi.where())
        response.raise_for_status()
        
        key_data = json.loads(response.text)
        modulus_b64 = key_data.get("modulus")
        exponent_b64 = key_data.get("exponent")
        
        if not modulus_b64 or not exponent_b64:
            raise ValueError(f"密钥接口返回数据不完整：{key_data}")
        
        return modulus_b64, exponent_b64
        
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"请求密钥接口失败：{e}")
    except ValueError:
        raise ValueError("密钥接口返回的不是有效JSON")

def jwxt_login(username: str, plain_password: str):
    """教务系统登录主函数"""
    try:
        csrftoken, doc = get_csrftoken()
        doc = pq(doc)
        
        if str(doc("input#yzm")) != "":
            return {"code": 1001, "msg": "需要验证码，当前版本不支持验证码登录"}
        
        modulus_b64, exponent_b64 = get_rsa_key()
        
        try:
            encrypted_password = rsa_encrypt_js_compatible(plain_password, modulus_b64, exponent_b64)
        except Exception as e:
            return {"code": 500, "msg": f"密码加密失败：{e}"}
        
        login_data = {
            "csrftoken": csrftoken,
            "language": "zh_CN",
            "ydType": "",
            "yhm": username,
            "mm": encrypted_password,
        }
        
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "https://jwxt.xjau.edu.cn",
            "Referer": "https://jwxt.xjau.edu.cn/jwglxt/xtgl/login_slogin.html",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        
        login_page_url = f"https://jwxt.xjau.edu.cn/jwglxt/xtgl/login_slogin.html?time={str(int(random.random() * 10**13))}"
        
        try:
            response = global_session.post(
                login_page_url,
                headers=headers,
                data=login_data,
                timeout=10,
                verify=certifi.where()
            )
            response.raise_for_status()
            login_response = response.text
                
        except requests.exceptions.RequestException as e:
            return {"code": 999, "msg": f"提交登录请求失败：{e}"}
        
        doc = pq(login_response)
        tips = doc("p#tips")
        
        if str(tips) != "":
            if "用户名或密码" in tips.text():
                return {"code": 1002, "msg": tips.text()}
            return {"code": 998, "msg": tips.text()}
        
        cookies_dict = {}
        for cookie in global_session.cookies:
            cookies_dict[cookie.name] = cookie.value
        
        return {
            "code": 1000, 
            "msg": "登录成功", 
            "data": {
                "cookies": cookies_dict,
                "cookies_string": "; ".join([f"{k}={v}" for k, v in cookies_dict.items()])
            }
        }
        
    except Exception as e:
        return {"code": 500, "msg": f"登录过程出错：{str(e)}"}

def get_semester_params():
    """
    智能获取学年学期参数，处理跨年情况
    返回适合当前时间的学年学期参数
    """
    from datetime import datetime
    
    now = datetime.now()
    current_year = now.year
    current_month = now.month
    
    # 学年和学期的判断逻辑
    if current_month >= 9:  # 9月及以后，秋季学期
        xnm = str(current_year)  # 学年以秋季开始年份为准
        xqm = "12"  # 秋季学期代码
        semester_name = f"{current_year}-{current_year+1}"
    elif current_month <= 2:  # 1-2月，仍属于上一学年的秋季学期
        xnm = str(current_year - 1)
        xqm = "12"
        semester_name = f"{current_year-1}-{current_year}"
    else:  # 3-8月，春季学期
        xnm = str(current_year - 1)  # 春季学期属于上一年开始的学年
        xqm = "03"  # 春季学期代码
        semester_name = f"{current_year-1}-{current_year}"
    
    return {
        "xnm": semester_name,
        "xqm": xqm
    }


def get_grades():
    """查询课程成绩"""
    url = "https://jwxt.xjau.edu.cn/jwglxt/cjcx/cjcx_cxXsgrcj.html?doType=query&gnmkdm=N305005"
    
    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Origin": "https://jwxt.xjau.edu.cn",
        "Referer": "https://jwxt.xjau.edu.cn/jwglxt/cjcx/cjcx_cxDgXscj.html?gnmkdm=N305005&layout=default",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "X-Requested-With": "XMLHttpRequest"
    }

    
   semester_params = get_semester_params()

    
    data = {
        "xnm": semester_params["xnm"],  # 空值表示获取所有学年
        "xqm": semester_params["xqm"],  # 空值表示获取所有学期
        "sfzgcj": "",
        "kcbj": "",
        "_search": "false",
        "nd": str(int(time.time() * 1000)),
        "queryModel.showCount": "50",
        "queryModel.currentPage": "1",
        "queryModel.sortName": "",
        "queryModel.sortOrder": "asc",
        "time": ""
    }
    
    try:
        response = global_session.post(
            url,
            headers=headers,
            data=data,
            timeout=10,
            verify=certifi.where()
        )
        response.raise_for_status()
        
        result = response.json()
        print(f"获取到 {len(result.get('items', []))} 条成绩记录")
        return {"code": 200, "msg": "查询成功", "data": result}
            
    except requests.exceptions.RequestException as e:
        return {"code": 999, "msg": f"请求失败：{e}"}
    except json.JSONDecodeError:
        return {"code": 300, "msg": "响应不是有效的JSON格式"}

def save_to_github_gist(data, gist_id, token):
    """保存数据到GitHub Gist"""
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

def compare_grades(old_grades, new_grades):
    """比较新旧成绩，返回变化信息"""
    changes = {
        "new_courses": [],
        "updated_scores": [],
        "total_changes": 0
    }
    
    if not old_grades or not old_grades.get("grades"):
        if new_grades and new_grades.get("items"):
            changes["new_courses"] = new_grades["items"]
            changes["total_changes"] = len(new_grades["items"])
        return changes
    
    old_items = {
        f"{item.get('kcmc', '')}_{item.get('kch', '')}_{item.get('jxb_id', '')}": item 
        for item in old_grades.get("grades", {}).get("items", [])
    }
    
    new_items = new_grades.get("items", [])
    
    for new_item in new_items:
        key = f"{new_item.get('kcmc', '')}_{new_item.get('kch', '')}_{new_item.get('jxb_id', '')}"
        
        if key not in old_items:
            changes["new_courses"].append(new_item)
            changes["total_changes"] += 1
        else:
            old_item = old_items[key]
            old_score = old_item.get("cj", "")
            new_score = new_item.get("cj", "")
            
            if old_score != new_score:
                changes["updated_scores"].append({
                    "course": new_item.get("kcmc", "未知课程"),
                    "course_code": new_item.get("kch", ""),
                    "old_score": old_score,
                    "new_score": new_score,
                    "semester": f"{new_item.get('njdm_id', '')}-学期",
                    "course_type": new_item.get("kcxzmc", ""),
                    "department": new_item.get("kkbmmc", "")
                })
                changes["total_changes"] += 1
    
    return changes

def send_wechat_notification(message, webhook_url):
    """发送微信通知"""
    if not webhook_url:
        print("未配置微信webhook，跳过通知发送")
        return False
        
    try:
        data = {
            "title": "成绩更新通知",
            "content": message
        }
        
        response = requests.post(webhook_url, json=data, timeout=10)
        if response.status_code == 200:
            print("微信通知发送成功")
            return True
        else:
            print(f"微信通知发送失败，状态码：{response.status_code}")
            return False
    except Exception as e:
        print(f"发送微信通知时出错：{e}")
        return False

def format_grade_change_message(changes):
    """格式化成绩变化消息"""
    if changes["total_changes"] == 0:
        return None
    
    message = f"成绩更新通知 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n\n"
    
    if changes["new_courses"]:
        message += f"新增成绩 ({len(changes['new_courses'])}门):\n"
        for course in changes["new_courses"]:
            course_name = course.get("kcmc", "未知课程")
            score = course.get("cj", "暂无")
            course_code = course.get("kch", "")
            course_type = course.get("kcxzmc", "")
            department = course.get("kkbmmc", "")
            year = course.get("njdm_id", "")
            
            message += f"  • {course_name}({course_code}): {score}\n"
            message += f"    [{course_type} | {department} | {year}]\n"
        message += "\n"
    
    if changes["updated_scores"]:
        message += f"成绩更新 ({len(changes['updated_scores'])}门):\n"
        for update in changes["updated_scores"]:
            message += f"  • {update['course']}({update['course_code']}): {update['old_score']} → {update['new_score']}\n"
            message += f"    [{update['course_type']} | {update['department']}]\n"
        message += "\n"
    
    message += f"总计变化: {changes['total_changes']} 项"
    return message

def main():
    """GitHub Actions专用主函数"""
    print(f"开始成绩监控 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 从环境变量获取配置
    username = os.environ.get('STUDENT_USERNAME')
    password = os.environ.get('STUDENT_PASSWORD')
    webhook_url = os.environ.get('WECHAT_WEBHOOK')
    github_token = os.environ.get('AGITHUB_TOKEN')
    gist_id = os.environ.get('GIST_ID')
    
    if not username or not password:
        print("错误：未设置学生用户名或密码")
        sys.exit(1)
    
    try:
        # 登录教务系统
        print("正在登录教务系统...")
        login_result = jwxt_login(username, password)
        
        if login_result.get("code") != 1000:
            print(f"登录失败：{login_result.get('msg', '未知错误')}")
            sys.exit(1)
        
        print("登录成功")
        
        # 获取最新成绩
        print("正在获取成绩数据...")
        result = get_grades()
        
        if result.get("code") != 200:
            print(f"成绩查询失败：{result.get('msg', '未知错误')}")
            sys.exit(1)
        
        new_grades = result.get("data")
        course_count = len(new_grades.get("items", []))
        print(f"成功获取 {course_count} 门课程的成绩")
        
        # 加载历史数据进行比较
        old_grades_data = load_from_github_gist(gist_id, github_token)
        
        # 比较成绩变化
        changes = compare_grades(old_grades_data, new_grades)
        print(f"成绩对比完成：新增 {len(changes['new_courses'])} 门，更新 {len(changes['updated_scores'])} 门")
        
        # 发送通知
        if changes["total_changes"] > 0:
            message = format_grade_change_message(changes)
            if message and webhook_url:
                if send_wechat_notification(message, webhook_url):
                    print("成绩变化通知已发送")
                else:
                    print("通知发送失败")
            else:
                print("检测到成绩变化但未配置微信通知")
                print("变化详情：")
                print(message)
        else:
            print("成绩无变化")
        
        # 保存最新数据
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
    main()
