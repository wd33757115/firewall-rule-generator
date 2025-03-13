import argparse
import logging
from collections import defaultdict
import concurrent.futures
import os
from typing import Dict, List

import pandas as pd

from core import NetworkTopology
from policy_engine import PolicyProcessor
from vendor_config import HuaweiConfigGenerator, H3CConfigGenerator, TopSecConfigGenerator, HillstoneConfigGenerator

logger = logging.getLogger(__name__)


def process_single_policy(processor: PolicyProcessor, row, ticket_id: str, user_id: str) -> Dict[str, List]:
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


def main():
    parser = argparse.ArgumentParser(description="防火墙策略生成工具（支持多用户和多线程）")
    parser.add_argument("-t", "--topology", required=True, help="拓扑JSON文件")
    parser.add_argument("-p", "--policies", required=True, help="策略Excel文件")
    parser.add_argument("-o", "--output", default="configs", help="输出目录")
    parser.add_argument("-u", "--user", default="default_user", help="用户标识")
    parser.add_argument("-w", "--workers", type=int, default=4, help="线程池工作线程数")
    args = parser.parse_args()

    # 为每个用户创建独立的输出目录
    user_output_dir = os.path.join(args.output, args.user)
    os.makedirs(user_output_dir, exist_ok=True)

    # 初始化拓扑和处理器
    topology = NetworkTopology(args.topology)
    df = pd.read_excel(args.policies, header=None, skiprows=3,
                       names=['src_ip', 'dst_ip', 'port', 'proto', 'action'])
    print(f"用户 {args.user} 的工单数据：\n{str(df)}")

    ticket_id = "2025022600001"  # 可根据用户或时间动态生成
    processor = PolicyProcessor(topology)
    all_firewall_rules = defaultdict(list)

    # 使用线程池处理工单
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_row = {
            executor.submit(process_single_policy, processor, row, ticket_id, args.user): row.name
            for _, row in df.iterrows()
        }
        for future in concurrent.futures.as_completed(future_to_row):
            idx = future_to_row[future]
            try:
                firewall_rules = future.result()
                for fw_name, rules in firewall_rules.items():
                    all_firewall_rules[fw_name].extend(rules)
            except Exception as e:
                logger.error(f"用户 {args.user} 策略 {idx} 处理失败: {str(e)}")

    # 为每个防火墙生成配置
    for fw_name, rules_list in all_firewall_rules.items():
        fw = topology.firewalls[fw_name]
        if fw.type == "华为":
            HuaweiConfigGenerator.generate(user_output_dir, fw_name, rules_list)
        elif fw.type == "H3C":
            H3CConfigGenerator.generate(user_output_dir, fw_name, rules_list)
        elif fw.type == "天融信":
            TopSecConfigGenerator.generate(user_output_dir, fw_name, rules_list)
        elif fw.type == "山石":
            HillstoneConfigGenerator.generate(user_output_dir, fw_name, rules_list)
        else:
            logger.error(f"用户 {args.user} 不支持的防火墙类型: {fw.type}")


if __name__ == "__main__":
    main()
