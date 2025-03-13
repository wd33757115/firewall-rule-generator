import logging
import os
from typing import List

logger = logging.getLogger(__name__)

class HuaweiConfigGenerator:
    @staticmethod
    def _format_address(ip_str: str, is_source: bool = True) -> List[str]:
        """格式化华为 USG6000F 系列的源/目的地址"""
        prefix = "source-address" if is_source else "destination-address"
        if '-' in ip_str and not ip_str.startswith('range'):
            base_ip = ip_str.rsplit('.', 1)[0]
            start_end = ip_str.split('.')[-1].split('-')
            start = f"{base_ip}.{start_end[0]}"
            end = f"{base_ip}.{start_end[1]}"
            return [f"{prefix} range {start} {end}"]
        elif '/' in ip_str:
            ip, prefix_len = ip_str.split('/')
            return [f"{prefix} {ip} {prefix_len}"]
        return [f"{prefix} {ip_str} 32"]

    @staticmethod
    def _format_ports(ports: set[str], proto: str) -> str:
        """格式化华为 USG6000F 系列的服务端口，支持范围和单端口混合"""
        if not ports:
            return f"service {proto}" if proto else "service any"

        # 将端口按数值排序并分组处理
        port_list = sorted(ports, key=lambda x: int(x.split('-')[0]) if '-' in x else int(x))
        formatted = []
        i = 0
        while i < len(port_list):
            if '-' in port_list[i]:
                # 直接添加范围端口
                start, end = port_list[i].split('-')
                formatted.append(f" {start} to  {end}")
                i += 1
            else:
                # 检查连续端口
                start = int(port_list[i])
                j = i + 1
                while j < len(port_list) and '-' not in port_list[j] and int(port_list[j]) == start + (j - i):
                    j += 1
                if j - i > 2:  # 如果连续端口超过2个，使用 range
                    end = int(port_list[j - 1])
                    formatted.append(f" {start} to  {end}")
                    i = j
                else:  # 单端口或少量非连续端口，单独列出
                    formatted.append(str(start))
                    i += 1

        ports_str = ' '.join(formatted)
        return f"service protocol {proto} destination-port {ports_str}"

    @staticmethod
    def _generate_rule(rule_data: dict, rule_index: int) -> List[str]:
        """生成华为 USG6000F 系列防火墙的安全策略规则"""
        src_zone, dst_zone = rule_data['rule_key']
        ticket_id = rule_data['ticket_id']
        config = [
            f"rule name {ticket_id}-{rule_index}",
            f"description {ticket_id}",
            f"source-zone {src_zone}",
            f"destination-zone {dst_zone}"
        ]

        # 配置源地址
        for src in rule_data.get("sources", []):
            config.extend(HuaweiConfigGenerator._format_address(src, is_source=True))

        # 配置目的地址
        for dst in rule_data.get("destinations", []):
            config.extend(HuaweiConfigGenerator._format_address(dst, is_source=False))

        # 配置服务和端口
        proto = rule_data.get("proto", "")
        ports = rule_data.get("ports", set())
        config.append(HuaweiConfigGenerator._format_ports(ports, proto))

        # 配置动作
        action = "permit" if rule_data.get("action", "").lower() == "permit" else "deny"
        config.append(f"action {action}")

        return config

    @staticmethod
    def generate(output_dir: str, fw_name: str, rules: List[dict]):
        """生成华为 USG6000F 系列防火墙的配置"""
        config = [
            "system-view",
            "security-policy",
        ]
        rule_index = 1
        for rule_data in rules:
            config.extend(HuaweiConfigGenerator._generate_rule(rule_data, rule_index))
            config.append("")  # 规则间换行
            rule_index += 1
        config.append("quit")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{fw_name}.txt")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join([line for line in config if line.strip()]))
        logger.info(f"生成华为防火墙配置: {output_path}")

class H3CConfigGenerator:
    @staticmethod
    def _format_address(ip_str: str, is_source: bool = True) -> List[str]:
        """格式化 H3C F50X0 系列的源/目的地址"""
        prefix = "source" if is_source else "destination"
        if '-' in ip_str and not ip_str.startswith('range'):
            base_ip = ip_str.rsplit('.', 1)[0]
            start_end = ip_str.split('.')[-1].split('-')
            start = f"{base_ip}.{start_end[0]}"
            end = f"{base_ip}.{start_end[1]}"
            return [f"{prefix}-ip-range {start} {end}"]
        elif '/' in ip_str:
            ip, mask = ip_str.split('/')
            return [f"{prefix}-ip-subnet {ip} {mask}"]
        return [f"{prefix}-ip-host {ip_str}"]

    @staticmethod
    def _format_ports(ports: set, proto: str) -> List[str]:
        """格式化 H3C F50X0 系列的服务端口"""
        if not ports:
            return []
        formatted = []
        for p in sorted(ports):
            if '-' in p:
                start, end = p.split('-')
                formatted.append(f"service-port {proto} destination range {start} {end}")
            else:
                formatted.append(f"service-port {proto} destination eq {p}")
        return formatted

    @staticmethod
    def _generate_rule(rule_data: dict, rule_index: int) -> List[str]:
        """生成 H3C F50X0 系列防火墙的安全策略规则"""
        src_zone, dst_zone = rule_data['rule_key']
        ticket_id = rule_data['ticket_id']
        config = [
            f"security-policy ip",
            f" rule {rule_index} name {ticket_id}-{rule_index}",
            f"  description {ticket_id}",
            f"  source-zone {src_zone}",
            f"  destination-zone {dst_zone}"
        ]

        # 配置源地址
        for src in rule_data.get("sources", []):
            config.extend([f"  {line}" for line in H3CConfigGenerator._format_address(src, is_source=True)])

        # 配置目的地址
        for dst in rule_data.get("destinations", []):
            config.extend([f"  {line}" for line in H3CConfigGenerator._format_address(dst, is_source=False)])

        # 配置服务和端口
        proto = rule_data['proto'] if rule_data['proto'] else 'ip'
        if ports := rule_data.get("ports"):
            config.extend(H3CConfigGenerator._format_ports(ports, proto))
        else:
            config.append(f"  service {proto}")

        # 配置动作
        action = "pass" if rule_data.get("action", "").lower() == "permit" else "deny"
        config.append(f"  action {action}")

        return config

    @staticmethod
    def generate(output_dir: str, fw_name: str, rules: List[dict]):
        """生成 H3C F50X0 系列防火墙的配置"""
        config = [
            "system-view",
        ]
        rule_index = 1
        for rule_data in rules:
            config.extend(H3CConfigGenerator._generate_rule(rule_data, rule_index))
            config.append("")
            rule_index += 1
        config.append("return")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{fw_name}.txt")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join([line for line in config if line.strip()]))
        logger.info(f"生成H3C防火墙配置: {output_path}")

class TopSecConfigGenerator:
    @staticmethod
    def _format_address(ip_str: str) -> List[str]:
        if '-' in ip_str and not ip_str.startswith('range'):
            base_ip = ip_str.rsplit('.', 1)[0]
            start_end = ip_str.split('.')[-1].split('-')
            start = f"{base_ip}.{start_end[0]}"
            end = f"{base_ip}.{start_end[1]}"
            mask = "255.255.255.254" if int(start_end[1]) - int(start_end[0]) == 1 else "255.255.255.252"
            return [f"source-address {start} {mask}"]
        elif '/' in ip_str:
            ip, mask = ip_str.split('/')
            mask_int = int(mask)
            subnet_mask = '.'.join([str((0xFFFFFFFF << (32 - mask_int)) >> (24 - 8*i) & 0xFF) for i in range(4)])
            return [f"source-address {ip} {subnet_mask}"]
        return [f"source-address {ip_str} 255.255.255.255"]

    @staticmethod
    def _format_ports(ports: set) -> str:
        formatted = []
        for p in sorted(ports):
            if '-' in p:
                start, end = p.split('-')
                formatted.append(f"{start}-{end}")
            else:
                formatted.append(p)
        return ' '.join(formatted)

    @staticmethod
    def _generate_rule(rule_data: dict, rule_index: int) -> List[str]:
        src_zone, dst_zone = rule_data['rule_key']
        ticket_id = rule_data['ticket_id']
        config = [
            f"security-policy",
            f" rule {rule_index} name {ticket_id}-{rule_index}",
            f"  description {ticket_id}",
            f"  source-zone {src_zone}",
            f"  destination-zone {dst_zone}"
        ]
        for src in rule_data.get("sources", []):
            config.extend([f"  {line}" for line in TopSecConfigGenerator._format_address(src)])
        for dst in rule_data.get("destinations", []):
            config.extend([f"  {line.replace('source', 'destination')}" for line in TopSecConfigGenerator._format_address(dst)])
        if ports := rule_data.get("ports"):
            ports_str = TopSecConfigGenerator._format_ports(ports)
            proto = rule_data['proto'] if rule_data['proto'] else 'ip'
            config.append(f"  service {proto} port {ports_str}")
        else:
            proto = rule_data['proto'] if rule_data['proto'] else 'ip'
            config.append(f"  service {proto}")
        action = "permit" if rule_data.get("action", "").lower() == "permit" else "deny"
        config.append(f"  action {action}")
        return config

    @staticmethod
    def generate(output_dir: str, fw_name: str, rules: List[dict]):
        config = [
            "configure",
        ]
        rule_index = 1
        for rule_data in rules:
            config.extend(TopSecConfigGenerator._generate_rule(rule_data, rule_index))
            config.append("")
            rule_index += 1
        config.append("exit")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{fw_name}.cfg")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join([line for line in config if line.strip()]))
        logger.info(f"生成天融信防火墙配置: {output_path}")

class HillstoneConfigGenerator:
    @staticmethod
    def _format_address(ip_str: str) -> List[str]:
        if '-' in ip_str and not ip_str.startswith('range'):
            base_ip = ip_str.rsplit('.', 1)[0]
            start_end = ip_str.split('.')[-1].split('-')
            start = f"{base_ip}.{start_end[0]}"
            end = f"{base_ip}.{start_end[1]}"
            mask = "255.255.255.254" if int(start_end[1]) - int(start_end[0]) == 1 else "255.255.255.252"
            return [f"address {start} mask {mask}"]
        elif '/' in ip_str:
            ip, mask = ip_str.split('/')
            mask_int = int(mask)
            subnet_mask = '.'.join([str((0xFFFFFFFF << (32 - mask_int)) >> (24 - 8*i) & 0xFF) for i in range(4)])
            return [f"address {ip} mask {subnet_mask}"]
        return [f"address {ip_str} mask 255.255.255.255"]

    @staticmethod
    def _format_ports(ports: set) -> str:
        formatted = []
        for p in sorted(ports):
            if '-' in p:
                start, end = p.split('-')
                formatted.append(f"{start}-{end}")
            else:
                formatted.append(p)
        return ' '.join(formatted)

    @staticmethod
    def _generate_rule(rule_data: dict, rule_index: int) -> List[str]:
        src_zone, dst_zone = rule_data['rule_key']
        ticket_id = rule_data['ticket_id']
        config = [
            f"policy security",
            f" rule {rule_index} name {ticket_id}-{rule_index}",
            f"  source zone {src_zone}",
            f"  destination zone {dst_zone}"
        ]
        for src in rule_data.get("sources", []):
            config.extend([f"  {line}" for line in HillstoneConfigGenerator._format_address(src)])
        for dst in rule_data.get("destinations", []):
            config.extend([f"  {line.replace('source', 'destination')}" for line in HillstoneConfigGenerator._format_address(dst)])
        if ports := rule_data.get("ports"):
            ports_str = HillstoneConfigGenerator._format_ports(ports)
            proto = rule_data['proto'] if rule_data['proto'] else 'ip'
            config.append(f"  service {proto} {ports_str}")
        else:
            proto = rule_data['proto'] if rule_data['proto'] else 'ip'
            config.append(f"  service {proto}")
        action = "permit" if rule_data.get("action", "").lower() == "permit" else "deny"
        config.append(f"  action {action}")
        return config

    @staticmethod
    def generate(output_dir: str, fw_name: str, rules: List[dict]):
        config = [
            "configure",
        ]
        rule_index = 1
        for rule_data in rules:
            config.extend(HillstoneConfigGenerator._generate_rule(rule_data, rule_index))
            config.append("")
            rule_index += 1
        config.append("exit")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{fw_name}.cfg")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join([line for line in config if line.strip()]))
        logger.info(f"生成山石防火墙配置: {output_path}")