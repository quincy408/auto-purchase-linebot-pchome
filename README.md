#MIS_IWantBuyGPUrrrr #開發者:周桂興 #非自由軟體 #有任何問題可以請教本人
本系統為支援Pchome24h電商，如亂使用本系統導致帳號被封鎖或相關法律責任，一律不關周桂興的事。

請將兩個檔案放在同個資料夾，並且事先安裝好所有模組

功能1:自動爬取RTX3090,RTX3080,6900XT,RTX3070,6800,6700XT,RTX3060的顯示卡，並去看是否有貨，如有貨會依照預算去購買到最大上限。
功能2:上一功能的自動化版，會定時檢測並去看是否有貨，如有貨會依照預算去購買到最大上限。
功能3:可自行新增商品ID(如:DABCEH-A900BFP86)，並使用輸入0來停止加入商品ID，他能定期追蹤剛剛以上輸入的商品是否有貨，如有貨便會自動購買。
功能4:輸入商品ID(如:DABCEH-A900BFP86)，按下enter後會立即下單。(可用來商品搶購或準點開賣時自行搶購)

UserData.txt文件Key介紹：
Json裡的Value請自行更改或新增(沒註解的請勿隨意更動)

"a":"a123456789@gmail.com"                 # 帳號
"p":"password"                             # 密碼
"PayWay": "ATM"                            # 付款方式 COD 為貨到付款、ATM 為 ATM 付款、IBO 為 ibon 付款
"CusName": "王小明"                         # 購買人姓名
"CusMobile": "0912345678"                  # 購買人連絡電話 - 手機
"AcceptEDM": "N"                           # 收貨地址顯示購買人姓名
"CusTel": "0412345678"                     # 購買人連絡電話 - 市話
"CusZip": "408"                            # 購買人郵遞區號
"CusAddress": "台中市...."                  # 購買人地址
"ShowCusName": "N"
"ContactNo": ""
"isSyncCust": "N"
"RecName": "王小明"                         # 收貨人中文姓名
"RecTel": "0412345678"                      # 收貨人連絡電話 - 市話
"RecMobile": "0912345678"                   # 收貨人連絡電話 - 手機
"RecZip": "408"                             # 收貨人郵遞區號
"RecAddress": "台中市...."                  # 收貨人地址
"AddContact": "N"                           # 資料加入收貨人通訊錄
"ConfirmIsLand": "N"
"RecMail": ""
"PaperInvoice": "N"                         # 是否願意將發票進行捐贈
"InvoiceType": "P"                          # 個人電子發票
"TaxNO": ""                                 # 發票種類為公司戶電子發票時，統一編號
"AddTaxNO": "N"                             # 資料加入公司統編備忘錄
"CashPoint": "0"
"Token": ""
"DeviceID": ""
"DeviceOS": ""
"DeviceName": ""
"DeviceOSVersion": ""
"DeviceAppVersion": ""
"IsSkipOTP": "N"
"availableDepositPoint": "0"
"availableVoucherPoint": "0"
"depositUsed": "0"
"voucherUsed": "0"
"BindMobile": ""
