# -*- coding: utf-8 -*-
"""
Created on Thu Jun  3 17:45:12 2021

@author: quincy408
"""

import re
import time
import json
import math
import random
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
#⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡一般插件⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡
import base64
from hashlib import md5
from Cryptodome import Random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_v1_5
#⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡資料加密⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡

def now_milliseconds():
    return str(math.floor(int(time.time() * 1000)))

def PersonalData():
    FrmData = UserData["FrmData"]
    return FrmData

BLOCK_SIZE = 16

def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + (chr(length)*length).encode()

def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

def bytes_to_key(data, salt, output=48):
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]

def encrypt(message, passphrase):
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))

def decrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))

def AkOutput():
    Passphrase = str(math.floor((random.random() * 1000000) + 1)).encode()
    Passphrase2 = now_milliseconds().encode()
    Ak = str(encrypt(Passphrase, Passphrase2))
    Ak = Ak.replace("b'", "")
    Ak = Ak.replace("'", "")
    return Ak

def EncryptionData(Ak,FrmData): #加密表單資料
    enFrmData = {}
    for i in FrmData:
        enData = str(encrypt(FrmData[i].encode(), Ak.encode()))
        enData = enData.replace("b'", "")
        enData = enData.replace("'", "")
        enFrmData[i] = enData
    return enFrmData

def SubmitOrder(enFrmData,Ak,enFrmUrl):
    PK, Token = PKTokenChack()
    Headers, LocalSession = CookieSET(ChromeCookies)
    PubKey = "-----BEGIN PUBLIC KEY-----" + PK + "-----END PUBLIC KEY-----"
    RsaKey = RSA.importKey(PubKey)
    cipher = PKCS1_v1_5.new(RsaKey)
    enAk = str(base64.b64encode(cipher.encrypt(Ak.encode())))
    enAk = enAk.replace("b'", "")
    enAk = enAk.replace("'", "")
    enFrmData['enAK'] = enAk 
    entoken = str(encrypt(Token.encode(), Ak.encode()))
    entoken = entoken.replace("b'", "")
    entoken = entoken.replace("'", "")
    enFrmData['Token'] = entoken
    enFrmReturn = LocalSession.get(enFrmUrl, headers = Headers, verify=False)
    enFrmReturn.encoding = 'UTF-8'
    soup1 = BeautifulSoup(enFrmReturn.text,"html5lib")
    rpcTK = soup1.find(id = 'recaptcha-token')['value']
    rpcFrmUrl = 'https://ecssl.pchome.com.tw/sys/cflow/fsapi/recaptcha'
    rpcFrmData = {'token':rpcTK}
    LocalSession.post(rpcFrmUrl, headers = Headers,data=rpcFrmData)
    recaptchaTK = str(encrypt(rpcTK.encode(), Ak.encode()))
    recaptchaTK = entoken.replace("b'", "")
    recaptchaTK = entoken.replace("'", "")
    enFrmData['recaptchaTK'] = recaptchaTK
    
    enFrmData = json.dumps(enFrmData, separators=(',', ':'))
    enFrmPost = {"frmData" : enFrmData,
           "CouponInfo": '{\"actData\":[],\"prodCouponData\":[]}'}
    enFrmUrl = 'https://ecssl.pchome.com.tw/sys/cflow/fsapi/BigCar/BIGCAR/OrderSubmit'
    enFrmReturn = LocalSession.post(enFrmUrl, headers = Headers,data = enFrmPost)
    enFrmReturn.encoding = 'UTF-8'
    return (enFrmReturn.text.encode("utf-8").decode('unicode-escape'))

#⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡加密函數⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡ 
def UpdataCookieAndTokenUrl(a, p):
    strr = ''
    chrome = webdriver.Chrome('./chromedriver')
    chrome.get("https://ecvip.pchome.com.tw/login/v3/login.htm?&rurl=https://ecssl.pchome.com.tw/sys/cflow/fsindex/BigCar/BIGCAR/ItemList")
    try:    
        WebDriverWait(chrome,10,0.1).until(EC.element_to_be_clickable((By.ID, "loginAcc")))
    finally:
        account = chrome.find_element_by_id("loginAcc")
        password = chrome.find_element_by_id("loginPwd")
    account.send_keys(a)
    password.send_keys(p)
    chrome.find_element_by_id("btnLogin").click()
    time.sleep(10)
    for elem in chrome.find_elements_by_xpath("/html/body/div[6]/div/div[1]/iframe"):
        TokenUrl = elem.get_attribute("src")
    Cookie = chrome.get_cookies()
    for c in Cookie:
        strr += c['name']
        strr += '='
        strr += c['value']
        strr += '; '
    full_cookie = strr
    full_cookie = full_cookie[:-2]
    chrome.quit()
    return full_cookie ,TokenUrl

def CookieSET(ChromeCookies):
    Cookie = {} 
    for item in ChromeCookies.split(';'):
        name, value = item.strip().split('=', 1)
        Cookie[name] = value
    Cookies = requests.utils.cookiejar_from_dict(Cookie, cookiejar=None, overwrite=True)
    LocalSession = requests.Session() 
    LocalSession.cookies = Cookies 
    Headers = { 
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://24h.pchome.com.tw',
            'x-requested-with': 'XMLHttpRequest',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36',
            'referer':'https://24h.pchome.com.tw/prod/DRAD1K-A900B8OUT?fq=/S/DRAD1K'
            }
    return Headers, LocalSession 
def PKTokenChack():
    Headers, LocalSession = CookieSET(ChromeCookies)
    PKURL = 'https://ecssl.pchome.com.tw/sys/cflow/fsapi/getPK'
    PKData = LocalSession.get(PKURL, headers=Headers)
    PKData.encoding = 'UTF-8' 
    try:
        PKData = PKData.json()
    except:
        print('未成功使用cookie登入 請檢查一下cookie是否正確')
        return 0, 0
    else:
        print('cookie與session成功登入')
        return PKData['PK'], PKData['Token'] 
def BasicRTXData(): 
    print('建置顯卡資料中 請稍等..')
    RTX = ['RTX3090','RTX3080','6900XT''RTX3070','6800','6700XT','RTX3060']
    RTXData = dict()
    RTXHaveQty = dict()
    Headers, LocalSession = CookieSET(ChromeCookies)
    for RTX in RTX:
        first = 1 
        Qtyfirst = 1
        time.sleep(random.randint(1,20))
        PrdIfURL = 'https://ecshweb.pchome.com.tw/search/v3.3/all/results?q={}'.format(RTX)
        PrdIfData = requests.get(PrdIfURL, headers = Headers)
        PrdIfData = PrdIfData.json()
        TotalPages = int(PrdIfData['totalPage'])
        for Pages in range(1, TotalPages + 1):
            time.sleep(1)
            PrdPageURL = 'https://ecshweb.pchome.com.tw/search/v3.3/all/results?q={}&page={}'.format(RTX, Pages)
            try:
                PrdPageData = LocalSession.get(PrdPageURL, headers = Headers)
            except:
                break
            while str(PrdPageData ) == "<Response [403]>":
                time.sleep(1)
                PrdPageData = LocalSession.get(PrdPageURL, headers = Headers)
                print('error')
            PrdPageData.encoding = 'UTF-8'
            PrdPageJson = PrdPageData.json()
            if  'RTX' in RTX :
                MiniChack = RTX[3:6]
            else:
                MiniChack = RTX[0:4]
            for rows in PrdPageJson['prods']:
                if 'DRAD' in rows['cateId'] and MiniChack in rows['name'] and '+' not in rows['name']:
                    time.sleep(1)
                    QtyURL = "https://mall.pchome.com.tw/ecapi/ecshop/prodapi/v2/prod/{}&fields=Qty&_callback=jsonp_prod&1587196620".format(rows['Id'])
                    try:
                        QtyData = LocalSession.get(QtyURL,headers = Headers)
                    except:
                        break
                    while str(QtyData) == "<Response [403]>":
                        time.sleep(1)
                        try:
                            QtyData = LocalSession.get(QtyURL,headers = Headers)
                        except:
                            print(rows['cateId'],'抓取失敗')
                            break
                    QtyData = re.sub('try{jsonp_prod\(|\}\);\}catch\(e\)\{if\(window.console\)\{console.log\(e\)\;\}','',QtyData.text) 
                    try: 
                        QtyJson = json.loads(QtyData)#轉為json
                    except:
                        print(rows['cateId'],'轉換失敗')
                        continue
                    else:
                        QtyId = rows['Id'] + "-000"
                        print(rows['name'] + ' 數量:' + str(QtyJson[QtyId]['Qty']))
                        if first == 1:
                            RTXData[RTX] = {rows['Id']:{'name':rows['name'],'price':rows['price'],'Qty':QtyJson[QtyId]['Qty']}}
                            first = 2
                            RTXData[RTX].setdefault(rows['Id'] , {'name':rows['name'],'price':rows['price'],'Qty':QtyJson[QtyId]['Qty']})
                            if QtyJson[QtyId]['Qty'] > 0:
                                if Qtyfirst == 1:
                                    RTXHaveQty[RTX] = {rows['Id']:{'name':rows['name'],'price':rows['price'],'Qty':QtyJson[QtyId]['Qty']}}
                                    Qtyfirst = 2
                                RTXHaveQty[RTX].setdefault(rows['Id'] , {'name':rows['name'],'price':rows['price'],'Qty':QtyJson[QtyId]['Qty']})
    return RTXData, RTXHaveQty 
    print('已成功抓取顯卡資料')

def Money():#預算
    money = int(input('預算:'))
    return money
    
def GetinCart(RTXHaveQty,money):
    PaySum = 0
    Headers, LocalSession = CookieSET(ChromeCookies)
    for BuyRTX in RTXHaveQty:
        for BuyId in RTXHaveQty[BuyRTX]: 
            if (PaySum + RTXHaveQty[BuyRTX][BuyId]['price']) < Money:
                MacUrl = 'https://24h.pchome.com.tw/prod/cart/v1/prod/'+ BuyId +'-000/snapup?_callback=jsonp_cartsnapup&' + str(now_milliseconds())
                MacDataContent = LocalSession.get(MacUrl, headers=Headers)
                MacData = MacDataContent.text.replace("try{jsonp_cartsnapup(", "")
                MacData = MacData.replace(");}catch(e){if(window.console){console.log(e);}}", "")
                MacData = json.loads(MacData)
                CartFrom = "{\"G\":[],\"A\":[],\"B\":[],\"TB\":\"24H\",\"TP\":2,\"T\":\"ADD\",\"TI\":\""+ BuyId +"-000\",\"RS\":\""+ BuyId[:6] +"\",\"YTQ\":1,\"CAX\":\"" + MacData['MAC'] + "\" ,\"CAXE\":\"" + MacData['MACExpire'] + "\"}"
                CartData = {'data' : CartFrom}
                CartUrl = 'https://24h.pchome.com.tw/fscart/index.php/prod/modify?callback=jsonp_addcart&' + str(now_milliseconds())
                CartReturn = LocalSession.post(CartUrl, headers = Headers,data = CartData)
                CartReturnData = CartReturn.text.replace("try{jsonp_addcart(", "")
                CartReturnData = CartReturnData.replace(");}catch(e){if(window.console){console.log(e);}}", "")
                CartReturnData = json.loads(CartReturnData)
                PaySum = CartReturnData['PRODTOTAL']
            else:
                break
    return PaySum

def OneClickBuy(UID,enFrmData,Ak):
    Headers, LocalSession = CookieSET(ChromeCookies)
    MacUrl = 'https://24h.pchome.com.tw/prod/cart/v1/prod/'+ UID +'-000/snapup?_callback=jsonp_cartsnapup&' + str(now_milliseconds())
    MacDataContent = LocalSession.get(MacUrl, headers=Headers)
    MacData = MacDataContent.text.replace("try{jsonp_cartsnapup(", "")
    MacData = MacData.replace(");}catch(e){if(window.console){console.log(e);}}", "")
    MacData = json.loads(MacData)
    CartFrom = "{\"G\":[],\"A\":[],\"B\":[],\"TB\":\"24H\",\"TP\":2,\"T\":\"ADD\",\"TI\":\""+ UID +"-000\",\"RS\":\""+ UID[:6] +"\",\"YTQ\":1,\"CAX\":\"" + MacData['MAC'] + "\" ,\"CAXE\":\"" + MacData['MACExpire'] + "\"}"
    CartData = {'data' : CartFrom}
    CartUrl = 'https://24h.pchome.com.tw/fscart/index.php/prod/modify?callback=jsonp_addcart&' + str(now_milliseconds())
    CartReturn = LocalSession.post(CartUrl, headers = Headers,data = CartData)
    CartReturnData = CartReturn.text.replace("try{jsonp_addcart(", "")
    CartReturnData = CartReturnData.replace(");}catch(e){if(window.console){console.log(e);}}", "")
    CartReturnData = json.loads(CartReturnData)
    time.sleep(1)
    print(SubmitOrder(enFrmData,Ak,enFrmUrl))
    return 0

def SearchListBuy(PrdList,enFrmData,Ak):
    Headers, LocalSession = CookieSET(ChromeCookies)
    localtime = time.localtime()
    SearchTime = time.strftime("%Y-%m-%d %I:%M:%S %p", localtime)
    print('----------------檢測時間為:',SearchTime,'---------------------')
    for Prd in PrdList:
        time.sleep(5)
        PrdPageURL = 'https://ecshweb.pchome.com.tw/search/v3.3/all/results?q={}'.format(Prd)
        try:
            PrdPageData = LocalSession.get(PrdPageURL, headers = Headers)
        except:
            break
        while str(PrdPageData ) == "<Response [403]>":
            time.sleep(1)
            PrdPageData = LocalSession.get(PrdPageURL, headers = Headers)
            print('error')
        PrdPageData.encoding = 'UTF-8'
        PrdPageJson = PrdPageData.json()
        for rows in PrdPageJson['prods']:
            print(rows['name'] + " 數量:" , end='')
        QtyURL = "https://mall.pchome.com.tw/ecapi/ecshop/prodapi/v2/prod/{}&fields=Qty&_callback=jsonp_prod&1587196620".format(Prd)
        try:
            QtyData = LocalSession.get(QtyURL,headers = Headers)
        except:
            break
        while str(QtyData) == "<Response [403]>":
            time.sleep(1)
            try:
                QtyData = LocalSession.get(QtyURL,headers = Headers)
                print(QtyData)
            except:
                print(Prd ,'抓取失敗')
                break
        QtyData = re.sub('try{jsonp_prod\(|\}\);\}catch\(e\)\{if\(window.console\)\{console.log\(e\)\;\}','',QtyData.text) 
        try: 
            QtyJson = json.loads(QtyData)
        except:
            print(Prd ,'轉換失敗')
            break
        print(str(QtyJson[Prd + "-000"]['Qty']))
        if QtyJson[Prd + "-000"]['Qty'] != 0:
            print(OneClickBuy(Prd,EncryptionData(Ak,PersonalData()),Ak))
            return True
    return False
#⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡一般函數⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡⇡

def Menu(Options,money,enFrmData,Ak,enFrmUrl):  
    while True:
        if Options == None:
            print("------------我想要買顯卡阿阿阿--------------")
            print("1.手動檢查(注意:有貨會直接下單)\n2.全自動檢查與購買\n3.追蹤網址與自動購買(適用於各式商品)\n4.一鍵購買(適用於各式商品)\n5.關閉程式\n\n註:2 與 3功能執行途中可按CTRL-C即可中斷跳出")
            Options = int(input("輸入要進行的選項："))
            print("-------------------------------------------")
            Menu(Options,money,enFrmData,Ak,enFrmUrl)
        else:
            if Options == 1:
                RTXData, RTXHaveQty = BasicRTXData()
                if RTXHaveQty == {}:
                    print('RTX3060, RTX3070, RTX3080, RTX3090, 6700XT, 6800, 6900XT中')
                    print('完全沒貨')
                else:
                    GetinCart(RTXHaveQty,money)
                    print('購買後回傳結果：',SubmitOrder(enFrmData,Ak,enFrmUrl))
            elif Options == 2:
                first = True
                try:
                    while True:
                        if first == False:
                            time.sleep(random.randint(900,1800))
                        first = False
                        localtime = time.localtime()
                        RTXData, RTXHaveQty = BasicRTXData()
                        SearchTime = time.strftime("%Y-%m-%d %I:%M:%S %p", localtime)
                        print('----------------檢測時間為:',SearchTime,'---------------------')
                        if RTXHaveQty == {}:
                            print('RTX3060, RTX3070, RTX3080, RTX3090, 6700XT, 6800, 6900XT中')
                            print('完全沒貨')
                        else:
                            GetinCart(RTXHaveQty,money)
                            time.sleep(2)
                            print('購買後回傳結果：',SubmitOrder(EncryptionData(Ak,PersonalData()),Ak,enFrmUrl))
                            break
                except KeyboardInterrupt:
                        print('跳出成功!')
            elif Options == 3:
                InputValue = ""
                PrdList = list()
                count = 1
                print("輸入0即可中斷")
                while InputValue != "0" or InputValue == "":
                    InputValue = input("第"+ str(count) +"次 請輸入商品ID:")
                    count = count + 1
                    if InputValue != "0":
                        PrdList.append(InputValue)
                print(PrdList)
                first = True
                try:
                    while True:
                    
                        if first == False:
                            time.sleep(random.randint(240,300))
                        first = False
                        if SearchListBuy(PrdList,enFrmData,Ak) == True:
                            break
                except KeyboardInterrupt:
                        print('跳出成功!')
            elif Options == 4:
                print("輸入商品UID後秒購買(輸入0取消)")
                UID = input('UID：')
                if UID != '0':
                    OneClickBuy(UID,EncryptionData(Ak,PersonalData()),Ak)
                Menu(None,money,enFrmData,Ak,enFrmUrl)
            elif Options == 5:
                print("關閉程式中")
                break
            else:
                print("輸入錯誤")
            Options = None
            time.sleep(4)

with open('UserData.txt',encoding="utf-8") as f:
    UserData = json.load(f)
a = UserData["user"]["a"]
p = UserData["user"]["p"]
ChromeCookies = None
ChromeCookies, enFrmUrl = UpdataCookieAndTokenUrl(a, p)
if __name__ == '__main__':
    PK,Token = PKTokenChack()
    if PK != '':
        Options = None
        money = Money()
        enFrmData = PersonalData()
        Ak = AkOutput()
        Menu(Options,money,enFrmData,Ak,enFrmUrl)
