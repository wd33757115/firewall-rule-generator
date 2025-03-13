import os
import logging
import re
from typing import Dict
from flask import Flask, request, render_template, send_file, Response, jsonify, abort, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
import pandas as pd
from collections import defaultdict
import concurrent.futures
from core import NetworkTopology
from policy_engine import PolicyProcessor
from vendor_config import HuaweiConfigGenerator, H3CConfigGenerator, TopSecConfigGenerator, HillstoneConfigGenerator
import zipfile
import io

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # 用于会话管理
logger = logging.getLogger(__name__)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 从 user.txt 读取用户数据
def load_users():
    VALID_USERS = {}
    try:
        with open('user.txt', 'r') as f:
            for line in f:
                username, password = line.strip().split(':')
                VALID_USERS[username] = generate_password_hash(password)
    except FileNotFoundError:
        logger.error("user.txt 文件未找到，使用默认用户")
        VALID_USERS = {"admin": generate_password_hash("password123")}
    return VALID_USERS

VALID_USERS = load_users()

def verify_user(username, password):
    """验证用户认证"""
    if username not in VALID_USERS or not check_password_hash(VALID_USERS[username], password):
        return False
    return True

def process_single_policy(processor: PolicyProcessor, row, ticket_id: str, user_id: str) -> Dict[str, list]:
    """处理单个工单的函数，用于多线程调用"""
    src_ips = str(row['src_ip']).replace('，', ',').replace('\n', ',').split(',')
    dst_ips = str(row['dst_ip']).replace('，', ',').replace('\n', ',').split(',')
    ports = str(row['port']).replace('，', ',').replace('\n', ',').split() if pd.notna(row['port']) else []
    proto = str(row['proto']) if pd.notna(row['proto']) else ''
    action = str(row['action'])

    result = processor.process_policy(src_ips, dst_ips, proto, ports, action, ticket_id)
    if result["error"]:
        logger.warning(f"用户 {user_id} 策略 {row.name} 处理失败: {result['error']}")
        return {}

    firewall_rules = defaultdict(list)
    for fw_name, fw_rules in result["firewall_rules"].items():
        for rule_key, rule_data in fw_rules.items():
            firewall_rules[fw_name].append({
                'rule_key': rule_key,
                'sources': rule_data['sources'],
                'destinations': rule_data['destinations'],
                'proto': rule_data['proto'],
                'ports': rule_data['ports'],
                'action': rule_data['action'],
                'ticket_id': rule_data['ticket_id']
            })
    return firewall_rules

@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if verify_user(username, password):
            session['user_id'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="用户名或密码错误")
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    """用户注销"""
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def index():
    """主页，处理文件上传和配置生成"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'GET':
        return render_template('index.html', message=None, files=None, user_id=user_id)

    policies_file = request.files.get('policies_file')
    topology_file = request.files.get('topology_file')

    if not policies_file:
        return render_template('index.html', message="请上传工单文件", files=None, user_id=user_id)

    topology_path = "topology_simple.json"
    if topology_file and topology_file.filename:
        topology_file.save(topology_path)
    elif not os.path.exists(topology_path):
        return render_template('index.html', message="拓扑文件未提供且默认文件不存在", files=None, user_id=user_id)

    policies_path = f"policies_{user_id}.xlsx"
    policies_file.save(policies_path)

    logger.info(f"用户 {user_id} 开始加载拓扑文件")
    topology = NetworkTopology(topology_path)
    df = pd.read_excel(policies_path, header=None, skiprows=3,
                       names=['src_ip', 'dst_ip', 'port', 'proto', 'action'])
    logger.info(f"用户 {user_id} 上传的工单数据：\n{str(df)}")
    total_policies = len(df)

    ticket_id = "2025022600001"
    processor = PolicyProcessor(topology)
    all_firewall_rules = defaultdict(list)
    processed_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_row = {
            executor.submit(process_single_policy, processor, row, ticket_id, user_id): row.name
            for _, row in df.iterrows()
        }
        for future in concurrent.futures.as_completed(future_to_row):
            idx = future_to_row[future]
            try:
                firewall_rules = future.result()
                processed_count += 1
                logger.info(f"用户 {user_id} 进度: 已处理 {processed_count}/{total_policies} 个策略")
                for fw_name, rules in firewall_rules.items():
                    all_firewall_rules[fw_name].extend(rules)
            except Exception as e:
                logger.error(f"用户 {user_id} 策略 {idx} 处理失败: {str(e)}")

    user_output_dir = os.path.join("configs", user_id)
    os.makedirs(user_output_dir, exist_ok=True)
    total_firewalls = len(all_firewall_rules)
    generated_count = 0
    success = True

    for fw_name, rules_list in all_firewall_rules.items():
        fw = topology.firewalls[fw_name]
        try:
            if fw.type == "华为":
                HuaweiConfigGenerator.generate(user_output_dir, fw_name, rules_list)
            elif fw.type == "H3C":
                H3CConfigGenerator.generate(user_output_dir, fw_name, rules_list)
            elif fw.type == "天融信":
                TopSecConfigGenerator.generate(user_output_dir, fw_name, rules_list)
            elif fw.type == "山石":
                HillstoneConfigGenerator.generate(user_output_dir, fw_name, rules_list)
            else:
                logger.error(f"用户 {user_id} 不支持的防火墙类型: {fw.type}")
                success = False
            generated_count += 1
            logger.info(f"用户 {user_id} 配置生成进度: 已生成 {generated_count}/{total_firewalls} 个防火墙配置")
        except Exception as e:
            logger.error(f"用户 {user_id} 生成 {fw_name} 配置失败: {str(e)}")
            success = False

    if os.path.exists(policies_path):
        os.remove(policies_path)
    if topology_file and topology_file.filename and os.path.exists(topology_path):
        os.remove(topology_path)

    message = f"配置生成{'成功' if success else '失败'}，用户 {user_id} 的文件位于 configs/{user_id}"
    return render_template('index.html', message=message, files=None, user_id=user_id)

@app.route('/download-config/<user_id>/<pattern>', methods=['GET'])
def download_config(user_id, pattern):
    """通过正则匹配返回用户的防火墙配置文件列表"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))

    logger.info(f"用户 {user_id} 请求下载配置，pattern: {pattern}")
    user_dir = os.path.join("configs", user_id)
    if not os.path.exists(user_dir):
        return render_template('index.html', message="用户配置目录未找到", files=None, user_id=user_id)

    try:
        regex = re.compile(pattern)
        matched_files = [
            filename for filename in os.listdir(user_dir)
            if regex.match(filename) and os.path.isfile(os.path.join(user_dir, filename))
        ]
        if not matched_files:
            return render_template('index.html', message=f"未找到匹配 '{pattern}' 的配置文件", files=None, user_id=user_id)

        files_info = [
            {"filename": filename, "download_url": f"/download-config-file/{user_id}/{filename}"}
            for filename in matched_files
        ]
        return render_template('index.html', message=f"找到 {len(matched_files)} 个匹配文件", files=files_info, user_id=user_id)
    except re.error:
        return render_template('index.html', message="无效的正则表达式", files=None, user_id=user_id)

@app.route('/download-config-file/<user_id>/<filename>', methods=['GET'])
def download_single_config_file(user_id, filename):
    """下载单个配置文件"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))

    config_path = os.path.join("configs", user_id, filename)
    if not os.path.exists(config_path) or not os.path.isfile(config_path):
        abort(404, description="配置文件未找到")

    return send_file(config_path, as_attachment=True, download_name=filename)

@app.route('/download-config-zip/<user_id>/<pattern>', methods=['GET'])
def download_config_zip(user_id, pattern):
    """下载匹配文件打包的 ZIP"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))

    user_dir = os.path.join("configs", user_id)
    if not os.path.exists(user_dir):
        abort(404, description="用户配置目录未找到")

    try:
        regex = re.compile(pattern)
        matched_files = [
            filename for filename in os.listdir(user_dir)
            if regex.match(filename) and os.path.isfile(os.path.join(user_dir, filename))
        ]
        if not matched_files:
            abort(404, description=f"未找到匹配 '{pattern}' 的配置文件")

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for filename in matched_files:
                file_path = os.path.join(user_dir, filename)
                zipf.write(file_path, filename)
        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"{user_id}_configs.zip"
        )
    except re.error:
        abort(400, description="无效的正则表达式")

@app.route('/delete-configs/<user_id>', methods=['POST'])
def delete_configs(user_id):
    """删除用户目录下的所有配置文件"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))

    user_dir = os.path.join("configs", user_id)
    if os.path.exists(user_dir):
        for filename in os.listdir(user_dir):
            file_path = os.path.join(user_dir, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
        logger.info(f"用户 {user_id} 的配置文件已删除")
        return render_template('index.html', message="所有配置文件已删除", files=None, user_id=user_id)
    return render_template('index.html', message="用户配置目录未找到", files=None, user_id=user_id)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=80, debug=None)