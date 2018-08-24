# coding: utf-8

import time
import os
import pwd
import sys
from urllib import urlencode
import subprocess
import json
import requests
import hmac
import hashlib
import base64


Request_url = "http://install-managesystem.webapp.163.com/task/getTask/"
Return_url = "http://install-managesystem.webapp.163.com/task/result/"


def project_clone(task):
    read_only_token = None
    git_address = task['git_address']
    url = git_address
    branch = task['branch']
    time_out = task['time_out']
    File = task['file']
    if 'read_only_token' in task:
        read_only_token = task['read_only_token']
    user_dir = pwd.getpwuid(os.getuid())[5]
    all_task_dir = os.path.join(user_dir, 'BuildTask')
    if os.path.exists(all_task_dir):
        pass
    else:
        os.mkdir(all_task_dir)
    url_list = url.split('/')
    pro_name = url_list[-1].split('.')[0]
    task_dir = os.path.join(all_task_dir, task['task_id'])
    # 当项目打包过程被撤回后再次运行此任务必须保证原撤回项目已经被删除
    if os.path.exists(task_dir):
        shutil.rmtree(task_dir)
    os.mkdir(task_dir)
    pro_dir = os.path.join(task_dir, pro_name)
    if read_only_token is not None:
        url = ('https://' + url_list[3] + ':' + read_only_token + '@' +
               url_list[2] + '/' + url_list[3] + '/' + url_list[4])
    print("cloning begin...")
    try:
        project_clone = subprocess.check_output(
                             ['git', 'clone', '-b', branch, url],
                             cwd=task_dir,
                             stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        log_contents = (err.output).decode('utf-8')
        error = 'project cloned failed'
        return {'description': error, 'result_status': err.returncode,
                'log_contents': log_contents}
    print("cloning finish")
    return {'pro_dir': pro_dir}


def build(task):
    clone_result = project_clone(task)
    if 'result_status' in clone_result:
        return clone_result
    else:
        pro_dir = clone_result['pro_dir']
        print('building begin...')
        result_status = 0
        try:
            project_build = subprocess.check_output(['scons'],
                                                    cwd=pro_dir,
                                                    stderr=subprocess.STDOUT)
            log_contents = project_build.decode('utf-8')
        except subprocess.CalledProcessError as err:
            log_contents = (err.output).decode('utf-8')
            result_status = err.returncode
        print("building finish")
        result = {'result_status': result_status, 'log_contents': log_contents}
        if result_status == 0:
            url_dir = os.path.join(pro_dir, 'url.txt')
            if os.path.exists(url_dir):
                url_file = open(url_dir)
                result_url = url_file.readlines()
                for i in range(len(result_url)):
                    result_url[i].strip('\n')
                url_file.close()
                result['result_url'] = result_url
            result['description'] = 'project building succeed'
        else:
            result['description'] = 'project building failed'
        return result


def Client(project, token, key):
    var = 1
    value = {'project': project, 'token': token}
    value = list(value.items())
    strToSign = urlencode(value)
    H = hmac.new(key, digestmod=hashlib.sha256)
    H.update(strToSign)
    digest = H.digest()
    signature = base64.b64encode(digest).decode()
    user_info = {'project': project, 'token': token, 'signature': signature}
    headers = {'content-type': 'application/json'}
    while var == 1:
        # request task
        r = requests.post(Request_url,
                          data=json.dumps(user_info), headers=headers)
        try:
            task = r.json()
        except Exception as e:
            print('Response error')
            return
        if 'error' in task:
            print('task error: ' + task['error'])
            return
        elif 'empty' in task:
            time.sleep(20)
            print(task['empty'])
            continue
        else:
            print('task: '+task['task_id']+' building begins...')
            # building task
            result = build(task)
            print(result['description'])
            result['token'] = token
            result['project'] = project
            result['task_id'] = task['task_id']
            # return building result
            value = [('project', project), ('token', token),
                     ('task_id', result['task_id']),
                     ('description', result['description']),
                     ('result_status', result['result_status'])]
            if 'log_contents' in result:
                value.append(('log_contents', result['log_contents']))
            if 'result_url' in result:
                value.append(('result_url', result['result_url']))
            strToSign = urlencode(value)
            H = hmac.new(key, digestmod=hashlib.sha256)
            H.update(strToSign)
            digest = H.digest()
            signature = base64.b64encode(digest).decode()
            result['signature'] = signature
            r = requests.post(Return_url, data=json.dumps(result),
                              headers=headers)
            feedback = r.json()
            if 'error' in feedback:
                print('server upload failed: ' + feedback['error'])
            else:
                print(feedback['succeed'])
