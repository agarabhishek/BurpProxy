# -text/plain .
# -text/html .
# --application/json .
# --application/xml .
# --text/xml .
# --application/x-www-form-urlencoded
# --multipart/form-data (Think can be split about =)
# -multipart/byteranges .
# --application/xhtml+xml
def content_type(self,re,re_body):
	con_type=0
	if re_body is not None:
		re_body_text=None
		content_type=re.headers.get('Content-Type','')

		if content_type.lower().startswith('application/json'):
	        try:
		      	#Aastha's function will give json
		        json_obj = json.loads(re_body)
		        json_str = json.dumps(json_obj, indent=2)
		        if json_str.count('\n') < 50:
		            re_body_text = json_str
		        else:
		            lines = json_str.splitlines()
		            res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
	    	except ValueError:
	        	re_body_text = re_body
	        con_type=1

	    if not (content_type.lower().startswith('application') or content_type.lower().startswith('text/xml')):
	    	re_body_text=re_body
	    	con_type=2

	    if content_type.lower().startswith('application/x') or content_type.lower().startswith('text/xml'):
	    	re_body_text=re_body
	    	con_type=3

	    if content_type.lower().startswith('application/x-www-form-urlencoded'):
	    	re_body_text=re_body
	    	con_type=4
	    if content_type.lower().startswith('multipart/form-data'):
	    	re_body_text=re_body
	    	con_type=5
	 	else:
	 		re_body_text=re_body
	 		con_type=0

	return re_body_text,con_type
