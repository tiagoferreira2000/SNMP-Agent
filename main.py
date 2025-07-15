import sys
import os
import json
import configparser
import logging
import threading
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pysnmp.hlapi import UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd, SnmpEngine
from pysnmp.hlapi.auth import CommunityData
from typing import Dict, List, Optional, Tuple
from collections import namedtuple
from enum import Enum


def get_config_path():
    """Obtém o caminho correto para o config.ini em modo normal ou empacotado"""
    try:
        # Se estiver executando como .exe empacotado
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
            
            # Tenta primeiro no diretório do executável
            exe_dir_config = os.path.join(base_path, 'config.ini')
            if os.path.exists(exe_dir_config):
                return exe_dir_config
            
            # Se não encontrar, tenta no diretório de trabalho
            cwd_config = os.path.join(os.getcwd(), 'config.ini')
            if os.path.exists(cwd_config):
                return cwd_config
            
            # Se ainda não encontrar, tenta no diretório de instalação do programa
            program_files_config = os.path.join(os.environ.get('ProgramFiles', ''), 'SnmpController', 'config.ini')
            if os.path.exists(program_files_config):
                return program_files_config
            
            # Se nenhum for encontrado, retorna o padrão
            return os.path.join(base_path, 'config.ini')
        
        # Se estiver executando como script Python
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')
    except Exception as e:
        logging.error(f"Erro ao determinar caminho do config.ini: {e}")
        return 'config.ini'  # Fallback


def setup_dependency_logger():
    """Configura logger para verificação de dependências"""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "dependency_check.log")
    
    logger = logging.getLogger('DependencyCheck')
    logger.setLevel(logging.DEBUG)
    
    handler = logging.FileHandler(log_file)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    
    return logger




def verify_dependencies():
    """Verifica todas as dependências do sistema"""
    logger = setup_dependency_logger()
    logger.info("="*50)
    logger.info("Iniciando verificação do ambiente Python")
    
    try:
        # Verifica caminhos importantes
        logger.info(f"Python path: {sys.executable}")
        logger.info(f"Python version: {sys.version}")
        
        # Verifica pacotes necessários
        required_packages = {
            'pysnmp': 'pysnmp',
            'requests': 'requests',
            'configparser': 'configparser'
        }
        
        missing = []
        installed = []
        
        try:
            from importlib import metadata
            installed_packages = {dist.metadata['Name'].lower(): dist.version 
                                for dist in metadata.distributions()}
        except:
            import pkg_resources
            installed_packages = {pkg.key.lower(): pkg.version 
                                for pkg in pkg_resources.working_set}
        
        for pkg_name, pkg_import in required_packages.items():
            try:
                __import__(pkg_import)
                version = installed_packages.get(pkg_name.lower(), 'presente')
                installed.append(f"{pkg_name} ({version})")
            except ImportError:
                missing.append(pkg_name)
        
        if missing:
            logger.error("Pacotes faltando: " + ", ".join(missing))
            logger.error("Pacotes instalados: " + ", ".join(installed))
            raise ImportError(f"Pacotes necessários faltando: {', '.join(missing)}")
        
        logger.info("Todos os pacotes necessários estão instalados")
        logger.info("Pacotes instalados: " + ", ".join(installed))
        
        # Verifica acesso a arquivos importantes
        config_path = get_config_path()
        accessible = os.access(config_path, os.R_OK) if os.path.exists(config_path) else False
        logger.info(f"Verificando acesso a {config_path} - Acessível: {accessible}")
        
        return True
        
    except Exception as e:
        logger.error(f"Falha na verificação do ambiente: {str(e)}", exc_info=True)
        return False


# Enhanced logging configuration
def setup_logging(config_path: str, service_name: str):
    """Configure comprehensive logging for the service"""
    try:
        config = configparser.ConfigParser()
        config.read(config_path)
        
        log_level = int(config.get('DEFAULT', 'loglevel', fallback='0'))
        log_days = int(config.get('DEFAULT', 'log_days', fallback='7'))
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"{service_name}_{datetime.now().strftime('%Y-%m-%d')}.log")
        
        # Clear existing handlers
        logging.root.handlers = []
        
        logging.basicConfig(
            level=logging.DEBUG if log_level == 2 else logging.INFO if log_level == 1 else logging.ERROR,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler(
                    log_file,
                    maxBytes=5*1024*1024,  # 5MB
                    backupCount=10,
                    encoding='utf-8'
                ),
                logging.StreamHandler()
            ]
        )
        
        # Log startup information
        logging.info(f"=== Starting {service_name} ===")
        logging.info(f"Python version: {sys.version}")
        logging.info(f"Working directory: {os.getcwd()}")
        logging.info(f"Script directory: {os.path.dirname(os.path.abspath(__file__))}")
        logging.info(f"Log level: {'DEBUG' if log_level == 2 else 'INFO' if log_level == 1 else 'ERROR'}")

        if sys.stderr:
            console_handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(formatter)
            logging.getLogger().addHandler(console_handler)
        
    except Exception as e:
        logging.error(f"Failed to configure logging: {str(e)}")
        raise




# Enums and Data Structures
class Frequency(Enum):
    HORA = 'hora'
    DIARIO = 'diario'
    MENSUAL = 'mensual'

Device = namedtuple('Device', ['name', 'nome_de_dispositivo', 'ip_local', 'denominacion', 'oid', 'frecuencia', 'ultimo_envio'])
Record = namedtuple('Record', ['dispositivo', 'denominacion', 'oid', 'value', 'frequencia'])


class SNMPService:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.sid_cookie = None
        self.session = self._create_session()
        self.logger.info("SNMPService initialized")


    def _create_session(self):
        """Create HTTP session with auto-retry"""
        self.logger.debug("Creating HTTP session with retry")
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session
        
    def run(self):
        """Main loop: execute monitoring every 5 minutes, only one instance."""
        self.logger.info("SNMPService main loop started. Will execute every 5 minutes.")
    
        # Variável para controle de parada
        self._running = True

        while self._running:
            try:
                self.logger.info("[CYCLE] Starting SNMP monitoring cycle...")
                self.main_logic()
                self.logger.info("[CYCLE] Monitoring cycle completed. Sleeping 5 minutes.")
            
                # Sleep não-bloqueante com verificação de parada
                for _ in range(300):  # 300 segundos = 5 minutos
                    if not self._running:
                        break
                    time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {str(e)}", exc_info=True)
                time.sleep(60)  # Espera 1 minuto em caso de erro antes de retentar
    
    def execute_monitoring(self):
        """Execute one monitoring cycle"""
        try:
            self.logger.info("Starting SNMP monitoring cycle...")
            self.main_logic()
            self.logger.info("Monitoring cycle completed successfully")
        except Exception as e:
            self.logger.error(f"Error during monitoring cycle: {str(e)}", exc_info=True)
            raise
    
    def load_config(self, config_path: str) -> Dict[str, str]:
        """Load INI config file with detailed logging, incluindo seção [DEFAULT]"""
        self.logger.debug(f"Loading config from: {config_path}")
        config = configparser.ConfigParser()
        try:
            if not os.path.exists(config_path):
                self.logger.error(f"Config file not found at: {config_path}")
                raise FileNotFoundError(f"Config file not found: {config_path}")
            config.read(config_path)
            # Converte para dicionário simples, incluindo seção DEFAULT
            config_dict = dict(config.defaults())
            for section in config.sections():
                for key, value in config.items(section):
                    config_dict[key] = value
                    self.logger.debug(f"Config loaded: {key} = {'*'*len(value) if 'password' in key.lower() else value}")
            return config_dict
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}", exc_info=True)
            raise

        
    def decrypt_password(self, encrypted: str) -> str:
        """Decrypt password using same algorithm as C# code"""
        self.logger.debug("Decrypting password")
        key = "CTGalegaEncKey2023!"
        decrypted = []
        
        try:
            for i in range(0, len(encrypted), 2):
                hex_byte = encrypted[i:i+2]
                encrypted_byte = int(hex_byte, 16)
                key_char = key[(i//2) % len(key)]
                decrypted_char = chr(encrypted_byte ^ ord(key_char))
                decrypted.append(decrypted_char)
                
            return ''.join(decrypted)
            
        except Exception as e:
            self.logger.error(f"Password decryption failed: {str(e)}", exc_info=True)
            raise
    
    def login_and_get_sid(self, base_url: str, username: str, password: str) -> Optional[str]:
        """Login and get SID cookie with detailed logging"""
        login_url = f"{base_url.rstrip('/')}/api/method/login"
        self.logger.info(f"Attempting login to: {login_url}")
        
        try:
            response = self.session.post(
                login_url,
                data={'usr': username, 'pwd': password},
                verify=False,  # Disable SSL verification - be careful in production!
                timeout=30
            )
            
            self.logger.info(f"Login response status: {response.status_code}")
            response.raise_for_status()
            
            # Check if 'sid' cookie was received
            if 'sid' in response.cookies:
                self.sid_cookie = f"sid={response.cookies['sid']}"
                self.logger.debug("SID cookie obtained successfully")
                return self.sid_cookie
                
            self.logger.error("SID cookie not found in response")
            return None
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Login request failed: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected login error: {str(e)}", exc_info=True)
            return None
            
    def get_devices_from_api(self, base_url: str, client_code: str, location_filter: str = None) -> Optional[List[Device]]:
        """Get devices from API with detailed logging"""
        url = f"{base_url.rstrip('/')}/api/resource/CI%20Dispositivo"
        self.logger.info(f"Fetching devices from API: {url}")
        
        filters = [["cliente", "=", client_code]]
        if location_filter:
            filters.append(["ubicacion", "=", location_filter])
        fields = [
            "name",
            "ip_local",
            "comprobacion.denominacion",
            "comprobacion.oid",
            "comprobacion.frecuencia",
            "comprobacion.ultimo_envio"
        ]
        params = {
            'fields': json.dumps(fields),
            'filters': json.dumps(filters),
            'limit_start': 0,
            'limit': 100
        }
        
        try:
            self.logger.debug(f"API request params: {params}")
            response = self.session.get(
                url, 
                params=params,
                headers={'Cookie': self.sid_cookie} if self.sid_cookie else None,
                timeout=30
            )
            
            self.logger.info(f"API response status: {response.status_code}")
            
            if response.status_code == requests.codes.unauthorized:
                self.logger.warning("SID cookie expired or invalid")
                return None
                
            response.raise_for_status()
            
            data = response.json().get('data', [])
            self.logger.info(f"Received {len(data)} devices from API")
            self.logger.info(f"API raw response data: {json.dumps(data, indent=2, ensure_ascii=False)}")
            # Convert to Device objects
            devices = []
            for item in data:
                try:
                    ultimo_envio = None
                    if item.get('ultimo_envio'):
                        try:
                            try:
                                ultimo_envio = datetime.fromisoformat(item['ultimo_envio'])
                            except Exception:
                                ultimo_envio = datetime.strptime(item['ultimo_envio'], "%Y-%m-%d %H:%M:%S.%f")
                        except Exception as e:
                            self.logger.warning(f"Invalid date format for ultimo_envio: {item['ultimo_envio']}")
                    device = Device(
                        name=item.get('name'),
                        nome_de_dispositivo=item.get('nome_de_dispositivo'),
                        ip_local=item.get('ip_local'),
                        denominacion=item.get('denominacion'),
                        oid=item.get('oid'),
                        frecuencia=item.get('frecuencia'),
                        ultimo_envio=ultimo_envio
                    )
                    devices.append(device)
                    self.logger.debug(f"Processed device: {device.name}")
                except Exception as e:
                    self.logger.error(f"Error processing device: {str(e)}", exc_info=True)
                    continue
            return devices
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting devices: {str(e)}", exc_info=True)
            raise

    def get_snmp_value(self, ip: str, oid: str, timeout: int = 5, retries: int = 2):
        try:
            # Adicione logging detalhado
            self.logger.debug(f"Tentando SNMP: {ip} OID: {oid} Timeout: {timeout}")
        
            error_indication, error_status, error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData('public', mpModel=0),  # mpModel=0 para SNMPv1
                UdpTransportTarget(
                    (ip, 161),
                    timeout=timeout,
                    retries=retries
                ),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            )
        
            if error_indication:
                self.logger.error(f"Erro SNMP: {error_indication}")
                return f"SNMP Error: {error_indication}"
            elif error_status:
                self.logger.error(f"Erro Status: {error_status.prettyPrint()}")
                return f"SNMP Error: {error_status.prettyPrint()}"
            else:
                for var_bind in var_binds:
                    value = str(var_bind[1])
                    self.logger.debug(f"Resposta SNMP: {value}")
                    return value
                
        except Exception as e:
            self.logger.error(f"Exceção SNMP: {str(e)}", exc_info=True)
            return f"SNMP Exception: {str(e)}"
            
    def should_execute_for_device(self, device: Device, frequency: Frequency) -> bool:
        """Determine if device should be executed based on frequency"""
        if not device.ultimo_envio:
            self.logger.debug(f"Device {device.name} has no last send time - will execute")
            return True
            
        time_diff = datetime.now() - device.ultimo_envio
        self.logger.debug(f"Device {device.name} last sent: {device.ultimo_envio} ({time_diff.total_seconds()} seconds ago)")
        
        if frequency == Frequency.HORA:
            return time_diff.total_seconds() >= 3600
        elif frequency == Frequency.DIARIO:
            return time_diff.total_seconds() >= 86400
        elif frequency == Frequency.MENSUAL:
            return time_diff.total_seconds() >= 2592000  # 30 days
        else:
            return True
        
    def main_logic(self):
        """Main service logic with comprehensive logging"""
        try:
            self.logger.info("Starting main service logic")
            
            config_path = get_config_path()
            self.logger.debug(f"Looking for config at: {config_path}")
            
            if not os.path.exists(config_path):
                self.logger.error(f"Config file not found at: {config_path}")
                return
                
            config = self.load_config(config_path)
            
            # Credential checks: require username and either password_enc or password
            username = config.get('username')
            password_enc = config.get('password_enc')
            password_plain = config.get('password')
            if not username:
                self.logger.error("Missing 'username' in config file")
                return
            if not password_enc and not password_plain:
                self.logger.error("Missing both 'password_enc' and 'password' in config file. At least one is required.")
                return
            if password_enc:
                password = self.decrypt_password(password_enc)
                if not password:
                    self.logger.error("Could not decrypt password from 'password_enc'")
                    return
            else:
                password = password_plain
                self.logger.warning("Using plaintext password from config file. This is insecure and should only be used for testing.")
                
            # Determine exe_dir for log cleanup
            if getattr(sys, 'frozen', False):
                exe_dir = os.path.dirname(sys.executable)
            else:
                exe_dir = os.path.dirname(os.path.abspath(__file__))
            # Clean up old logs
            self.cleanup_old_logs(exe_dir, int(config.get('log_days', '7')))
            
            self.logger.info("Starting SNMP monitoring cycle")
            
            # Authentication
            if not self.sid_cookie:
                self.sid_cookie = self.login_and_get_sid(
                    config['service_url'],
                    config['username'],
                    password
                )
                if not self.sid_cookie:
                    self.logger.error("Could not get authentication SID")
                    return
                    
            # Get devices
            devices = self.get_devices_from_api(
                config['service_url'],
                config['client_code'],
                config.get('location_filter')
            )
            
            if not devices:
                # Try to renew SID
                self.logger.warning("No devices received - attempting to renew SID")
                self.sid_cookie = self.login_and_get_sid(
                    config['service_url'],
                    config['username'],
                    password
                )
                if not self.sid_cookie:
                    self.logger.error("Could not renew authentication SID")
                    return
                    
                devices = self.get_devices_from_api(
                    config['service_url'],
                    config['client_code'],
                    config.get('location_filter')
                )
                
                if not devices:
                    self.logger.error("No devices obtained even after renewing SID")
                    return
                    
            if not devices:
                self.logger.warning("No devices returned by API. Ending processing.")
                return
                
            # Process by frequency
            for freq in Frequency:
                self.logger.info(f"[{freq.value}] Processing frequency")
                
                filtered_devices = [
                    d for d in devices
                    if d.frecuencia and d.frecuencia.lower() == freq.value
                    and self.should_execute_for_device(d, freq)
                ]
                
                self.logger.info(f"[{freq.value}] Devices ready to process: {len(filtered_devices)}")
                
                if not filtered_devices:
                    self.logger.info(f"[{freq.value}] No devices to process for this frequency")
                    continue
                    
                collected_data = []
                
                for device in filtered_devices:
                    device_name = device.nome_de_dispositivo or device.name or "Unknown"
                    self.logger.debug(f"Processing device: {device_name}")
                    
                    if not device.ip_local or not device.oid:
                        self.logger.warning(f"[{freq.value}] Device '{device_name}' ignored: IP or OID missing")
                        continue
                        
                    value = self.get_snmp_value(device.ip_local, device.oid)
                    
                    if value and value not in ['No response', 'Invalid SNMP'] and not value.startswith('SNMP Error'):
                        collected_data.append(Record(
                            dispositivo=device_name,
                            denominacion=device.denominacion,
                            oid=device.oid,
                            value=value,
                            frequencia=freq.value
                        ))
                        self.logger.debug(f"Collected data from {device_name}: {value}")
                    else:
                        self.logger.warning(f"[{freq.value}] Device '{device_name}' ignored: invalid SNMP value ('{value}')")
                        
                if collected_data:
                    result = self.send_data_to_api(config, collected_data)
                    if result:
                        self.logger.info(f"[{freq.value}] Successfully sent {len(collected_data)} records to API")
                    else:
                        self.logger.warning(f"[{freq.value}] Failed to send data to API")
                else:
                    self.logger.info(f"[{freq.value}] No valid data collected - nothing sent")
                    
                self.logger.info(f"[{freq.value}] Frequency processing completed")
                
        except Exception as e:
            self.logger.error(f"FATAL ERROR in main logic: {str(e)}", exc_info=True)
            raise
            
    def cleanup_old_logs(self, log_dir: str, log_days: int):
        """Remove old logs with detailed logging"""
        log_dir = os.path.join(log_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        self.logger.debug(f"Cleaning up old logs in: {log_dir}")
        
        if not os.path.exists(log_dir):
            self.logger.debug("Log directory does not exist - nothing to clean")
            return
            
        limit_date = datetime.now() - timedelta(days=log_days)
        self.logger.info(f"Removing logs older than: {limit_date}")
        removed_count = 0
        
        for filename in os.listdir(log_dir):
            if filename.startswith("snmp_log_") and filename.endswith(".txt"):
                try:
                    filepath = os.path.join(log_dir, filename)
                    file_date_str = filename[9:19]  # Extract yyyy-MM-dd
                    file_date = datetime.strptime(file_date_str, "%Y-%m-%d")
                    
                    if file_date < limit_date:
                        os.remove(filepath)
                        removed_count += 1
                        self.logger.debug(f"Removed old log: {filename}")
                except Exception as e:
                    self.logger.error(f"Error removing old log {filename}: {str(e)}")
        
        self.logger.info(f"Removed {removed_count} old log files")
                    
    def send_data_to_api(self, config: Dict, data: List[Record]) -> bool:
        """Send data to API with comprehensive logging"""
        url = f"{config['service_url'].rstrip('/')}/api/resource/CI%20Registro"
        self.logger.info(f"Sending data to API: {url}")
        
        # Group by device
        grouped_data = {}
        for item in data:
            if item.dispositivo not in grouped_data:
                grouped_data[item.dispositivo] = []
            grouped_data[item.dispositivo].append(item)
            
        success = True
        total_devices = len(grouped_data)
        processed_devices = 0
        
        self.logger.info(f"Preparing to send data for {total_devices} devices")
        
        for device_name, items in grouped_data.items():
            processed_devices += 1
            self.logger.debug(f"Processing device {processed_devices}/{total_devices}: {device_name}")
            
            payload = {
                'dispositivo': device_name,
                'comprobacion': [{
                    'denominacion': item.denominacion,
                    'oid': item.oid,
                    'valor': item.value
                } for item in items]
            }
            
            try:
                self.logger.debug(f"Sending payload for {device_name}: {json.dumps(payload)}")
                response = self.session.post(
                    url,
                    json=payload,
                    headers={
                        'Content-Type': 'application/json',
                        'Cookie': self.sid_cookie
                    },
                    timeout=30
                )
                
                if response.status_code == requests.codes.unauthorized:
                    self.logger.warning("SID cookie expired or invalid when sending data")
                    success = False
                    continue
                    
                response.raise_for_status()
                self.logger.debug(f"Successfully sent data for {device_name}")
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error sending data for {device_name}: {str(e)}")
                success = False
            except Exception as e:
                self.logger.error(f"Unexpected error sending data for {device_name}: {str(e)}", exc_info=True)
                success = False
                
        return success

if __name__ == '__main__':
    print("[INFO] Rodando em modo console (NSSM)")
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('snmp_console.log')
        ]
    )
    if not verify_dependencies():
        print("Erro: Verificação de dependências falhou. Verifique o arquivo dependency_check.log")
        logging.error("Erro: Verificação de dependências falhou. Verifique o arquivo dependency_check.log")
        sys.exit(1)
    service = SNMPService()
    service.run()

