from time import sleep
from config import Config
import psycopg2
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import socket, psutil


#vars
host = Config.HOST
port = Config.PORT
dbname = Config.DBNAME
user = Config.USER
password = Config.PASSWORD 

options = webdriver.ChromeOptions()
options.add_experimental_option("excludeSwitches", ["enable-automation"])
options.add_argument("--user-data-dir=C:/Users/user/AppData/Local/Google/Chrome/User Data/Profile 4")
options.add_argument("--profile-directory=Default")
driver = webdriver.Chrome(options=options)
driver.maximize_window()

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

def start_up():
    driver.get("http://192.168.1.37:5000/")

    try:

        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password   
        )
        cursor = conn.cursor()
            
        cursor.execute(f"SELECT username, password_hash FROM users WHERE ip_address LIKE '{local_ip}';")
        records = cursor.fetchall()
        for record in records:
            username = record[0]
            password_hash = record[1]
            
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Bağlantı hatası: {e}")
        exit()

    UserName = driver.find_element(By.XPATH, '//*[@id="username"]')
    Password = driver.find_element(By.XPATH, '//*[@id="password"]')
    LoginButton = driver.find_element(By.XPATH, '/html/body/div/div[2]/form/div[3]/button')
    UserName.send_keys(username)
    Password.send_keys(password_hash)
    LoginButton.click()

start_up()
while 1:
    sleep(1)
    is_running = any("chrome.exe" in p.name().lower() for p in psutil.process_iter())

    if not is_running:
        driver = webdriver.Chrome(options=options)
        driver.minimize_window()
        start_up()
        
    else:
        sleep(1)



