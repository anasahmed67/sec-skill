def write_temp(content):
    f = open('/tmp/temp_app_data.txt', 'w')
    f.write(content)
    f.close()
