import json
import uuid
import requests
import time
import hashlib


appid= 1404
appkey="70851B95-FA6B-4CC6-BFCD-03A3AC9E7BEE"
signKey="fLlTyxVU5b3IAY"
version="1"

token =""
uname =""



#####加密算法,需要替换成自己的
def whole_up(pass_data):
    bytedata = bytes(pass_data,"utf8")
    mKey = [238,108,204,241,178,19,68,186,213,241,34]
    ret = ""
    for i in range(len(bytedata)):
        ret = ret+Hex((bytedata[i] + 124 ^ mKey[i % len(mKey)]) & 255)

    return ret
#####解密算法,需要替换成自己的
def whole_down(data):
    mKey = [158,139,55,151,184,235,168,93,179,28,160,68,131,215]
    table = []
    datebyte = bytearray()
    for i in range(0,len(data),2):
        table.append(H2d(data[i:i+2]))
    for i in range(0, len(table)):
        datebyte.append((((table[i] ^ mKey[i % len(mKey)]))+50)&255)

    return datebyte.decode("utf8")


def public_public(data,nonce):

    timestamp = int(time.time())
    print("时间戳",timestamp)
    sign= hashlib.new('md5', bytes(str(appid)+nonce+signKey+str(timestamp)+data, "utf8")).hexdigest()
    print("sign",sign)
    return json.dumps({"appid":appid,"nonce":nonce,"timestamp":timestamp,"data":data,"sign":sign})


#软件初始化
#请求获取到软件的初始化信息，如软件公告、基础信息、最新版本、md5、是否更新等有关软件的信息
def appInit():
    nonce=str(uuid.uuid1())
    send={
        "appkey":appkey,
        "version":version
    }
    #上面都不要动

    ret=requests.post("http://bgp.tyserve.net/v1/appInit",public_public(whole_up(json.dumps(send)),nonce))
    retJson=json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson



# 请求用户账号密码的登录，成功后将返回 token令牌、过期时间、点数、qq号、邮箱、手机号;
# 其中token令牌用于需要认证的接口鉴权,不传入或错误将不通过.
def userLogin(userName,upwd):
    url="http://bgp.tyserve.net/v1/userLogin"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "uname": userName,
        "upwd": upwd,
        "version": version,
        "mac": get_mac_address()
    }

    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)

    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""

        global uname
        uname = userName
        global token
        token = retJson["data"]["token"]

    return retJson


# 请求卡密模式的登陆,成功后将返回 token令牌、过期时间、点数;
# 其中token令牌用于需要认证的接口鉴权,不传入或错误将不通过.
def cdkeyLogin (cdkey):
    url="http://bgp.tyserve.net/v1/cdkeyLogin"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "cdkey": cdkey,
        "version": version,
        "mac": get_mac_address()
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""

        global uname
        uname = cdkey
        global token
        token = retJson["data"]["token"]
    return retJson


# 该接口用于用户登录模式的账号密码注册
def userRegin(userName,upwd,spwd,key,invite,email,phone,qq):
    url="http://bgp.tyserve.net/v1/userRegin"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "uname": userName,
        "upwd": upwd,
        "spwd": spwd,
        "upwd": upwd,
        "mac": get_mac_address(),
        "key": key,
        "invite": invite,
        "email": email,
        "phone": phone,
        "qq": qq,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson

# 用于注册用户的充值,不可用于单码用户的充值.
def userRecha(userName,key):
    url="http://bgp.tyserve.net/v1/userRecha"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "uname": userName,
        "key": key,
        "mac": get_mac_address()
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 修改密码(changePwd)
def changePwd(userName,pwd,npwd):
    url="http://bgp.tyserve.net/v1/changePwd"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "uname": userName,
        "pwd": pwd,
        "npwd": npwd
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 可通过安全密码修改注册用户的登录密码
def resetPwd(userName,spwd,npwd):
    url="http://bgp.tyserve.net/v1/resetPwd"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "uname": userName,
        "spwd": spwd,
        "npwd": npwd
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于注册用户或单码用户的设备解绑,前提是后台设置可自行解绑
def userBind(userName,upwd,utype):
    url="http://bgp.tyserve.net/v1/userBind"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "uname": userName,
        "upwd": upwd,
        "utype": utype
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用户退出登录,软件结束时必须调用,否则可能会影响用户的下次登录.
def logOut():
    url="http://bgp.tyserve.net/v1/logOut"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于获取用户当前状态,如:是否过期、异地登录、是否锁定、是否被踢下线等,请求时间要大于十分钟否则直接返回频繁调用错误;
def getUserStatus():
    url="http://bgp.tyserve.net/v1/getUserStatus"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于获取用户信息,如邮箱、qq号、手机号、用户组、点数、过期时间、用户数据、用户备注,单码用户只返回 用户组、点数、过期时间、用户数据、用户备注;
def getUserProfile():
    url="http://bgp.tyserve.net/v1/getUserProfile"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于设置用户信息,如邮箱、qq、手机号、用户数据.
def setUserProfile(email,phone,qq,data):
    url="http://bgp.tyserve.net/v1/setUserProfile"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
        "email": email,
        "phone": phone,
        "qq": qq,
        "data": data,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson

# 用于获取软件的核心数据,重要数据放到服务器上,做数据分离;
def getAppCore():
    url="http://bgp.tyserve.net/v1/getAppCore"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于获取版本信息如版本状态、版本md5、版本数据、更新地址、更新内容.
def getVerCore():
    url="http://bgp.tyserve.net/v1/getVerCore"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于获取软件变量数据,重要数据放到服务器上,做数据分离;
def getVarCore(vid,vname):
    url="http://bgp.tyserve.net/v1/getVarCore"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
        "vid": vid,
        "vname": vname,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于客户端扣除用户点数
def setUserTally(take):
    url="http://bgp.tyserve.net/v1/setUserTally"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
        "take": take,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于封停违规用户
def setUserDisable(note):
    url="http://bgp.tyserve.net/v1/setUserDisable"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
        "note": note,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于获取用户权限
def getUserPower():
    url="http://bgp.tyserve.net/v1/getUserPower"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 可用于软件的用户留言或反馈
def setAppMessage(version,contact,message):
    url="http://bgp.tyserve.net/v1/setAppMessage"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "token": token,
        "uname": uname,
        "version": version,
        "contact": contact,
        "message": message,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


# 用于检测到破解后将机器码或IP添加到黑名单,用户将无法登录并自动封停.
def setAppBlack(type,note):
    url="http://bgp.tyserve.net/v1/setAppBlack"
    nonce = str(uuid.uuid1())
    send = {
        "appkey": appkey,
        "mac": get_mac_address(),
        "type": type,
        "note": note,
    }
    ret = requests.post(url, public_public(whole_up(json.dumps(send)), nonce))
    retJson = json.loads(ret.text)
    if retJson["status"]==200:
        retJson["data"] = json.loads(whole_down(retJson["data"]))
        if retJson["data"]["nonce"]=="":
            retJson["data"] = ""
        if nonce != retJson["data"]["nonce"]:
            retJson["data"] = ""
        if (int(time.time()) - retJson["data"]["timestamp"]) >500 :
            retJson["data"] = ""
    return retJson


def get_mac_address():
    node = uuid.getnode()
    mac = uuid.UUID(int =node ).hex [-12:]
    return mac




########################################################################################################################




def Hex(date):
    ret = str(hex(date))
    if len(ret)%2 == 1:
        return str.upper("0"+ret[-1])
    return str.upper(ret[-2:])

def H2d(str):
    t = "0123456789ABCDEF"
    date = ""
    ret=0
    for i in range(0,len(str)):
        # print(str[i] , t.find(str[i]))
        ret=ret*16+t.find(str[i])
    return ret