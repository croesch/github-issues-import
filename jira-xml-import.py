#!/usr/bin/env python3

import xml.etree.ElementTree as ET

import urllib.request, urllib.error, urllib.parse
import json
import base64
import sys, os
import datetime
import argparse, configparser
import re
import query

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
default_config_file = os.path.join(__location__, 'config.ini')
config = configparser.RawConfigParser()

def init_config():
	
	config.add_section('login')
	config.add_section('source')
	config.add_section('target')
	config.add_section('format')
	config.add_section('settings')
	
	arg_parser = argparse.ArgumentParser(description="Import issues from one GitHub repository into another.")
	
	config_group = arg_parser.add_mutually_exclusive_group(required=False)
	config_group.add_argument('--config', help="The location of the config file (either absolute, or relative to the current working directory). Defaults to `config.ini` found in the same folder as this script.")
	config_group.add_argument('--no-config', dest='no_config',  action='store_true', help="No config file will be used, and the default `config.ini` will be ignored. Instead, all settings are either passed as arguments, or (where possible) requested from the user as a prompt.")
	
	arg_parser.add_argument('-u', '--username', help="The username of the account that will create the new issues. The username will not be stored anywhere if passed in as an argument.")
	arg_parser.add_argument('-p', '--password', help="The password (in plaintext) of the account that will create the new issues. The password will not be stored anywhere if passed in as an argument.")
	arg_parser.add_argument('-s', '--source', help="The source file to import from.")
	arg_parser.add_argument('-t', '--target', help="The destination repository which the issues should be copied to. Should be in the format `user/repository`.")
	
	arg_parser.add_argument('--ignore-comments',  dest='ignore_comments',  action='store_true', help="Do not import comments in the issue.")		
	arg_parser.add_argument('--ignore-milestone', dest='ignore_milestone', action='store_true', help="Do not import the milestone attached to the issue.")
	arg_parser.add_argument('--ignore-labels',    dest='ignore_labels',    action='store_true', help="Do not import labels attached to the issue.")
	
	include_group = arg_parser.add_mutually_exclusive_group(required=True)
	include_group.add_argument("--all", dest='import_all', action='store_true', help="Import all issues, regardless of state.")
	include_group.add_argument("--open", dest='import_open', action='store_true', help="Import only open issues.")
	include_group.add_argument("--closed", dest='import_closed', action='store_true', help="Import only closed issues.")
	include_group.add_argument("-i", "--issues", type=int, nargs='+', help="The list of issues to import.");

	args = arg_parser.parse_args()
	
	def load_config_file(config_file_name):
		try:
			config_file = open(config_file_name)
			config.read_file(config_file)
			return True
		except (FileNotFoundError, IOError):
			return False
	
	if args.no_config:
		print("Ignoring default config file. You may be prompted for some missing settings.")
	elif args.config:
		config_file_name = args.config
		if load_config_file(config_file_name):
			print("Loaded config options from '%s'" % config_file_name)
		else:
			sys.exit("ERROR: Unable to find or open config file '%s'" % config_file_name)
	else:
		config_file_name = default_config_file
		if load_config_file(config_file_name):
			print("Loaded options from default config file in '%s'" % config_file_name)
		else:
			print("Default config file not found in '%s'" % config_file_name)
			print("You may be prompted for some missing settings.")

	
	if args.username: config.set('login', 'username', args.username)
	if args.password: config.set('login', 'password', args.password)
	
	if args.source: config.set('source', 'file', args.source)
	if args.target: config.set('target', 'repository', args.target)
	
	config.set('settings', 'import-comments',  str(not args.ignore_comments))
	config.set('settings', 'import-milestone', str(not args.ignore_milestone))
	config.set('settings', 'import-labels',    str(not args.ignore_labels))
	
	config.set('settings', 'import-open-issues',   str(args.import_all or args.import_open));
	config.set('settings', 'import-closed-issues', str(args.import_all or args.import_closed));
	
	
	# Make sure no required config values are missing
	if not config.has_option('source', 'file') :
		sys.exit("ERROR: There is no source repository specified either in the config file, or as an argument.")
	if not config.has_option('target', 'repository') :
		sys.exit("ERROR: There is no target repository specified either in the config file, or as an argument.")
	
	
	def get_server_for(which):
		# Default to 'github.com' if no server is specified
		if (not config.has_option(which, 'server')):
			config.set(which, 'server', "github.com")
		
		# if SOURCE server is not github.com, then assume ENTERPRISE github (yourdomain.com/api/v3...)
		if (config.get(which, 'server') == "github.com") :
			api_url = "https://api.github.com"
		else:
			api_url = "https://%s/api/v3" % config.get(which, 'server')
		
		config.set(which, 'url', "%s/repos/%s" % (api_url, config.get(which, 'repository')))
	
	get_server_for('target')
	
	
	# Prompt for username/password if none is provided in either the config or an argument
	def get_credentials_for(which):
		if not config.has_option(which, 'username'):
			if config.has_option('login', 'username'):
				config.set(which, 'username', config.get('login', 'username'))
			elif ( (which == 'target') and query.yes_no("Do you wish to use the same credentials for the target repository?") ):
				config.set('target', 'username', config.get('source', 'username'))
			else:
				query_str = "Enter your username for '%s' at '%s': " % (config.get(which, 'repository'), config.get(which, 'server'))
				config.set(which, 'username', query.username(query_str))
		
		if not config.has_option(which, 'password'):
			if config.has_option('login', 'password'):
				config.set(which, 'password', config.get('login', 'password'))
			elif ( (which == 'target') and config.get('source', 'username') == config.get('target', 'username') and config.get('source', 'server') == config.get('target', 'server') ):
				config.set('target', 'password', config.get('source', 'password'))
			else:
				query_str = "Enter your password for '%s' at '%s': " % (config.get(which, 'repository'), config.get(which, 'server'))
				config.set(which, 'password', query.password(query_str))
	
	get_credentials_for('target')
	
	# Everything is here! Continue on our merry way...
	return args.issues or []

def send_request(which, url, post_data=None):

	if post_data is not None:
		post_data = json.dumps(post_data).encode("utf-8")
	
	full_url = "%s/%s" % (config.get(which, 'url'), url)
	req = urllib.request.Request(full_url, post_data)
	
	username = config.get(which, 'username')
	password = config.get(which, 'password')
	req.add_header("Authorization", b"Basic " + base64.urlsafe_b64encode(username.encode("utf-8") + b":" + password.encode("utf-8")))
	
	req.add_header("Content-Type", "application/json")
	req.add_header("Accept", "application/json")
	req.add_header("User-Agent", "IQAndreas/github-issues-import")
	
	try:
		response = urllib.request.urlopen(req)
		json_data = response.read()
	except urllib.error.HTTPError as error:
		
		error_details = error.read();
		error_details = json.loads(error_details.decode("utf-8"))
		
		if error.code in http_error_messages:
			sys.exit(http_error_messages[error.code])
		else:
			error_message = "ERROR: There was a problem importing the issues.\n%s %s" % (error.code, error.reason)
			if 'message' in error_details:
				error_message += "\nDETAILS: " + error_details['message']
			sys.exit(error_message)
	
	return json.loads(json_data.decode("utf-8"))


def getIssues():
  issues = []

  tree = ET.parse(config.get('source', 'file'))
  root = tree.getroot()

  channel = root.find('channel')
  for issue_node in channel.iter('item'):
    issue = {}
    issue_data = {}
    issue['title'] = issue_node.find('summary').text
    reporter_node =  issue_node.find('reporter')
    issue_data['issue_creator_username'] = reporter_node.text
    issue_data['issue_creator_url'] = 'http://jira.codehaus.org/secure/ViewProfile.jspa?name=' + reporter_node.attrib['username']
    issue_data['issue_date'] = issue_node.find('created').text
    issue_data['issue_url'] = issue_node.find('link').text
    issue_data['issue_body'] = issue_node.find('description').text
    issue['body'] = format_issue(issue_data) + """

----

votes (original issue): """ + issue_node.find('votes').text + """
watches (original issue): """ + issue_node.find('watches').text + """
"""
    issue['labels'] = []
    issue['labels'].append(issue_node.find('priority').text)
    issue['labels'].append(issue_node.find('type').text)

    comments = []

    attachments = []
    attachments_node = issue_node.find('attachments')
    if attachments_node is not None:
        for attachment_node in attachments_node.iter('attachment'):
            attachment_data = {}
            attachment_data['comment_creator_username'] = attachment_node.attrib['author']
            attachment_data['comment_creator_url'] = 'http://jira.codehaus.org/secure/ViewProfile.jspa?name=' + attachment_node.attrib['author']
            attachment_data['comment_date'] = attachment_node.attrib['created']
            attachment_data['comment_body'] = 'Attachment [' + attachment_node.attrib['name'] + '](http://jira.codehaus.org/secure/attachment/' + attachment_node.attrib['id'] + '/) (size=' + attachment_node.attrib['size'] + ')'

            comments.append(attachment_data)

    comments_node = issue_node.find('comments')
    if comments_node is not None:
        for comment_node in comments_node.iter('comment'):
            comment_data = {}
            comment_data['comment_creator_username'] = comment_node.attrib['author']
            comment_data['comment_creator_url'] = 'http://jira.codehaus.org/secure/ViewProfile.jspa?name=' + comment_node.attrib['author']
            comment_data['comment_date'] = comment_node.attrib['created']
            comment_data['comment_body'] = comment_node.text

            comments.append(comment_data)
    
    issue['comments'] = comments
    issues.append(issue)
  return issues

def format_issue(template_data): 
  default_template = os.path.join(__location__, 'templates', 'issue.md')
  template = config.get('format', 'issue_template', fallback=default_template)
  return format_from_template(template, template_data)

def format_comment(template_data):
	default_template = os.path.join(__location__, 'templates', 'comment.md')
	template = config.get('format', 'comment_template', fallback=default_template)
	return format_from_template(template, template_data)

def format_from_template(template_filename, template_data):
  from string import Template
  template_file = open(template_filename, 'r')
  template = Template(template_file.read())
  return template.substitute(template_data)

def import_comments(comments, issue_number):
	result_comments = []
	for template_data in comments:
		comment = {}	
		comment['body'] = format_comment(template_data)

		result_comment = send_request('target', "issues/%s/comments" % issue_number, comment)
		result_comments.append(result_comment)
		
	return result_comments

def import_issues(issues):
	result_issues = []
	for issue in issues:
		
		result_issue = send_request('target', "issues", issue)
		print("Successfully created issue '%s'" % result_issue['title'])
		
		if 'comments' in issue:
			result_comments = import_comments(issue['comments'], result_issue['number'])		
			print(" > Successfully added", len(result_comments), "comments.")
		
		result_issues.append(result_issue)
	
	return result_issues

init_config()
import_issues(getIssues())
