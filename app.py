import os
import socket
from urllib.parse import urlparse

import requests
import validators
from bs4 import BeautifulSoup, Comment
from flask import Flask, render_template, request

app = Flask(__name__)

default_config = {'forms': True, 'comments': True, 'passwords': True,
                  'SSL': True, 'CSS': True, 'JS': True, 'PortScan': False}


def extract_hostname(link):
    """extract host name"""
    return os.path.dirname(link)


def extract_link(link):
    """removes scheme(http or https) from the link"""
    return link.replace('https://', '').replace('http://', '')


def portscan_check(link):

    portscan_link = extract_link(link)
    if portscan_link.endswith('/'):
        portscan_link = extract_hostname(portscan_link)

    if default_config['PortScan']:
        ports = [25, 67, 135, 136, 137, 138,
                 139, 161, 445, 520, 547, 1080, 1900]
        for port in ports:
            print(port, portscan_link)
            s = socket.socket()
            result_portscan = s.connect_ex((portscan_link, port))
            print(result_portscan)
            s.close()
            if result_portscan == 0:
                return f'Port {str(port)} is open. Please ensure if this port needs to be kept open. <br/>'

            else:
                return 'No vulnerable ports open.'


def pass_check(bs4html):
    if default_config['passwords']:
        password_inputs = bs4html.find_all('input', {'type': 'password'})

        if len(password_inputs) == 0:
            return 'No password fields found! <br/>'
        for password_input in password_inputs:
            return 'Password Input Issue! Plaintext password input was found. Please change to password type. <br/>' if (password_input.get('type') != 'password') else 'Password type used for password field. No password input issue. <br/>'


def forms_check(bs4html, link):
    forms = bs4html.find_all('form')
    if default_config['forms']:
        report = ''
        hostname = extract_hostname(link)
        for form in forms:
            if (link in form.get('action')):
                if ((form.get('action').find('https') < 0)):
                    report += 'Insecure Form action! ' + \
                        form.get('action') + \
                        ' form is not secure with https. <br/> '
                else:
                    form_x = form.get('action')
                    form_index = int(form_x.find('?'))
                    form_new = form_x[:form_index]
                    report += f'{form_new} form is secure with https. <br/> '
            else:
                form_x = form.get('action')
                form_index = form_x.find('?')
                form_new = form_x[:form_index]
                report += f'{form_new} form is secure with https. <br/> '
        return report


def comments_check(bs4html):
    if default_config['comments']:
        comments = bs4html.find_all(
            string=lambda text: isinstance(text, Comment))

        if len(comments) == 0:
            return 'No keys/secrets found in comments. <br/>'
        for comment in comments:
            return 'Comment Issue! A Key/Secret is found in the HTML code in comments. Please remove the key. <br/>' if (comment.find('key') > -1) else 'No keys/secrets found in comments <br/>'


def ssl_check(link):

    if default_config['SSL']:
        link_scheme = urlparse(link).scheme

        if link_scheme == 'https':
            return 'SSL Secure (Includes HTTPS). <br/>'
        elif link_scheme == 'http':
            link = f'https{link[4:]}'
            if requests.get(link).status_code == 200:
                return 'SSL secured version of site exists. <br/>'
            return 'SSL doesn\'t exist'


def css_check(requested_html):

    report = ""
    if(default_config['CSS']):
        print('Working on CSS')
        uses_css = (requested_html.text.find('<link rel="stylesheet"') > -1)
        report += 'The provided url contains Cascading Style Sheet(CSS). <br/>'
    return report


def js_check(requested_html):

    report = ""
    if(default_config['JS']):
        print('Working on JS')
        uses_js = (requested_html.text.find(
            '<script language="text/javascript"') > -1)
        report += 'The provided url contains JavaScript. <br/>'
    return report


@app.route("/")
def home():

    return render_template('index.html')


@app.route("/result", methods=['POST', 'GET'])
def result():

    if request.method == 'POST':
        result = request.form
        link = result.get('URL')
        print(link)
        if (validators.url(link)):
            requested_html = requests.get(link)
            bs4_parsed_html = BeautifulSoup(
                requested_html.text, 'html.parser')  # forms,comments,passwords
            if requested_html.status_code != 200:
                return render_template('result.html', result=['Expecting status code 200 but received ' + str(requested_html.status_code)])

            tests_link = [ssl_check]
            tests_html = [css_check, js_check]
            tests_bs4 = [comments_check, pass_check]

            def inner():
                for test in tests_link:
                    yield test(link)
                yield forms_check(bs4_parsed_html, link)
                for test in tests_html:
                    yield test(requested_html)
                for test in tests_bs4:
                    yield test(bs4_parsed_html)

            return render_template('result.html', result=inner())
        else:
            result = ''
            return render_template('result.html', result=['Link is not valid. Please enter link in the format http://yourdomain.com'])


if __name__ == '__main__':
    app.run(debug=True)
