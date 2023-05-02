import TYAPI as ty

if __name__ == '__main__':

    ret=ty.appInit()



    ret = ty.userLogin("test01","123123")

    if ret["status"] != 200:

        if int(ret["status"]) != 0:
            print("当前网络异常")

        else:
            print(ret["msg"])


    else:

        print("过期时间：",ret["data"]["finaltime"])
