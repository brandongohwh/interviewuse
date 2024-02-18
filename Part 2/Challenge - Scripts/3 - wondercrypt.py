# wondercrypt
import base64

def m0a(string):
    string = base64.b64decode(str.encode(string))
    strlist = []
    for i in string:
        if i-7>=0:
            strlist.append(chr((i-7) ^ 193))
        else:
            strlist.append(chr((i-7+256)^193))
    return ''.join(strlist)

print(m0a("lZE="))