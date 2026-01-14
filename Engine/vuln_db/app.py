import os 
import sys 

from flask import Flask, request, jsonify
from flask_cors import CORS
current_directory = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_directory, '.')

# Add the folder path to sys.path
sys.path.append(db_path)

# Import the file as a module
import_module = __import__("db")

app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})


# Vulnerabilty Database

@app.route('/getspecificcwe/<int:cwe_id>', methods=['GET'])
def get_cwe(cwe_id):
    try:
        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT * FROM vul_db WHERE cwe_id = %s"
        cursor.execute(select_query, (cwe_id,))
        data = cursor.fetchone()
        cursor.close()
        import_module.close_connection(conn)

        if data:
            # Convert record to a dictionary for JSON response
            data_dict = {
                'cwe_id': data[0],
                'vuln_name': data[1],
                'vuln_description': data[2],
                'severity': data[3],
                'risk_score': data[4]
            }
            return data_dict
        else:
            return 'CWE not found'
        
    except Exception as e:
        return 'Error retrieving CWE: ' + str(e)

@app.route('/getcwe', methods=['GET'])
def get_all_cwe():
    try:
        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT * FROM vul_db"
        cursor.execute(select_query)
        data = cursor.fetchall()
        cursor.close()
        import_module.close_connection(conn)

        if data:
            # Convert record to a dictionary for JSON response
            data_list = []
            for data in data:
                data_dict = {
                'cwe_id': data[0],
                'name': data[1],
                'description': data[2],
                'severity': data[3],
                'risk_score': data[4]
                }
                data_list.append(data_dict)
            
            return {'CWE': data_list}
        else:
            return 'No CWEs found'
        
    except Exception as e:
        return 'Error retrieving CWE: ' + str(e)
    
@app.route('/addcwe', methods=['POST'])
def insert_cwe():
    try:
        # Retrieve data from the request
        cwe_id = request.json['cwe_id']
        name = request.json['name']
        description = request.json['description']
        severity = request.json['severity']
        risk_score = request.json['risk_score']

        # Perform the insert operation
        conn = import_module.connect()
        cursor = conn.cursor()
        insert_query = "INSERT INTO vul_db (cwe_id, name, description, severity, risk_score) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(insert_query, (cwe_id, name, description, severity, risk_score))
        conn.commit()
        cursor.close()
        import_module.close_connection(conn)

        return 'Record inserted successfully'
    
    except Exception as e:
        return 'Error inserting CWE: ' + str(e)

@app.route('/editcwe/<int:cwe_id>', methods=['PUT'])
def update_cwe(cwe_id):
    try:
         # Retrieve the fields to update from the request payload
        update_fields = request.json

        # Perform the update operation
        conn = import_module.connect()
        cursor = conn.cursor()

        for field, value in update_fields.items():
            update_query = f"UPDATE vul_db SET {field} = %s WHERE cwe_id = %s"
            cursor.execute(update_query, (value, cwe_id))
        
        conn.commit()
        cursor.close()
        import_module.close_connection(conn)
        
        return 'CWE updated successfully'

    except Exception as e:
        return 'Error updating CWE: ' + str(e)


@app.route('/deletecwe/<int:cwe_id>', methods=['DELETE'])
def delete_cwe(cwe_id):
    try:
        # Perform the delete operation
        conn = import_module.connect()
        cursor = conn.cursor()
        delete_query = "DELETE FROM vul_db WHERE cwe_id = %s"
        cursor.execute(delete_query, (cwe_id,))
        conn.commit()
        cursor.close()
        import_module.close_connection(conn)

        return 'Record deleted successfully'

    except Exception as e:
        return 'Error deleting CWE: ' + str(e)
    
# Vulnerable Pattern Database
@app.route('/get_specific_cwe_vuln_pattern/<int:cwe_id>', methods=['GET'])
def get_cwe_vuln_pattern(cwe_id):
    try:
        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT vpdb.cwe_id, vsdb.name, vsdb.description, vpdb.vuln_response, vsdb.severity, vsdb.risk_score FROM vuln_script_pattern_db vpdb join vul_db vsdb on vpdb.cwe_id = vsdb.cwe_id WHERE vpdb.cwe_id  = %s"
        cursor.execute(select_query, (cwe_id,))
        data = cursor.fetchall()
        cursor.close()
        import_module.close_connection(conn)

        if data:
            data_list = []
            for data in data:
            # Convert record to a dictionary for JSON response
                data_dict = {
                    'cwe_id': data[0],
                    'vuln_name': data[1],
                    'vuln_description': data[2],
                    'vuln_response': data[3],
                    'severity': data[4],
                    'risk_score': data[5]
                }
                data_list.append(data_dict)
            return {'CWE': data_list}
        else:
            return 'CWEs not found'
        
    except Exception as e:
        return 'Error retrieving CWE: ' + str(e) 
    
# Result Scan Database

@app.route('/getspecificscan', methods=['GET'])
def get_specific_scan_result():
    try:
        scan_uuid = request.json.get('scan_uuid')
        if not scan_uuid:
            return "scan_uuid is missing in the request body"
        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT * FROM result_scan_db WHERE scan_uuid = %s"
        cursor.execute(select_query, (scan_uuid,))
        data = cursor.fetchall()
        cursor.close()
        import_module.close_connection(conn)

        if data:
            # Convert record to a dictionary for JSON response
            data_list = []
            for data in data:
                data_dict = {
                    'scan_id': data[0],
                    'scan_uuid': data[1],
                    'start_time': data[2],
                    'end_time': data[3],
                    'low_vuln': data[4],
                    'med_vuln': data[5],
                    'high_vuln': data[6],
                    'host_ip': data[7],
                    'risk_score': data[8]
                }
                data_list.append(data_dict)
            
            return {'Results': data_list}
        else:
            return f'{scan_uuid} not found'
        
    except Exception as e:
        return 'Error retrieving results: ' + str(e)
    
@app.route('/getresults', methods=['GET'])
def get_all_scan_result():
    try:
        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT * FROM result_scan_db"
        cursor.execute(select_query)
        data = cursor.fetchall()
        cursor.close()
        import_module.close_connection(conn)

        if data:
            # Convert record to a dictionary for JSON response
            data_list = []
            for data in data:
                data_dict = {
                    'scan_id': data[0],
                    'scan_uuid': data[1],
                    'start_time': data[2],
                    'end_time': data[3],
                    'low_vuln': data[4],
                    'med_vuln': data[5],
                    'high_vuln': data[6],
                    'host_ip': data[7],
                    'risk_score': data[8]
                }
                data_list.append(data_dict)
            
            return {'Results': data_list}
        else:
            return 'No results found'
        
    except Exception as e:
        return 'Error retrieving results: ' + str(e)
    
@app.route('/addscanresult', methods=['POST'])
def insert_scan_result():
    try:
        # Retrieve data from the request
        scan_uuid = request.json['scan_uuid']
        start_time = request.json['start_time']
        end_time = request.json['end_time']
        low_vuln = request.json['low_vuln']
        med_vuln = request.json['med_vuln']
        high_vuln = request.json['high_vuln']
        host_ip = request.json['host_ip']
        risk_score = request.json['risk_score']

        # Perform the insert operation
        conn = import_module.connect()
        cursor = conn.cursor()
        insert_query = "INSERT INTO result_scan_db (scan_uuid, start_time, end_time, low_vuln, med_vuln, high_vuln, host_ip, risk_score) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(insert_query, (scan_uuid, start_time, end_time, low_vuln, med_vuln, high_vuln, host_ip, risk_score))
        conn.commit()
        cursor.close()
        import_module.close_connection(conn)

        return 'Record inserted successfully'
    
    except Exception as e:
        return 'Error inserting result: ' + str(e)

@app.route('/editscanresult/<int:result_id>', methods=['PUT'])
def update_result(result_id):
    try:
         # Retrieve the fields to update from the request payload
        update_fields = request.json

        # Perform the update operation
        conn = import_module.connect()
        cursor = conn.cursor()

        for field, value in update_fields.items():
            update_query = f"UPDATE result_db SET {field} = %s WHERE result_scan_id = %s"
            cursor.execute(update_query, (value, result_id))
        
        conn.commit()
        cursor.close()
        import_module.close_connection(conn)
        
        return f'{result_id} updated successfully'

    except Exception as e:
        return 'Error updating result: ' + str(e)


@app.route('/deletescanresult/<int:result_id>', methods=['DELETE'])
def delete_result(result_id):
    try:
        # Perform the delete operation
        conn = import_module.connect()
        cursor = conn.cursor()
        delete_query = "DELETE FROM result_db WHERE result_id = %s"
        cursor.execute(delete_query, (result_id,))
        conn.commit()
        cursor.close()
        import_module.close_connection(conn)

        return f'{result_id} deleted successfully'

    except Exception as e:
        return 'Error deleting result: ' + str(e)
        
@app.route('/getlatestresultscanuuid', methods=['GET'])
def get_latest_result_scan_uuid():
    try:
        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT scan_uuid FROM result_scan_db ORDER BY scan_uuid DESC LIMIT 1"
        cursor.execute(select_query)
        latest_scan_uuid = cursor.fetchone()
        cursor.close()
        import_module.close_connection(conn)

        if latest_scan_uuid:
            latest_scan_uuid = latest_scan_uuid[0]  # Unpack the result from the tuple
            return {'latest_scan_uuid': latest_scan_uuid}
        else:
            return 'No scan_uuid found in the result_scan_db table.'
        
    except Exception as e:
        return 'Error retrieving the latest scan_uuid: ' + str(e)
    

# Result Vulnerabilities Scanned Database
@app.route('/getallvulnscaninfo', methods=['GET'])
def get_all_vuln_info():
    try:
        scan_uuid = request.json.get('scan_uuid')

        if not scan_uuid:
            return "scan_uuid is missing in the request body"

        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT r.* FROM ( SELECT *, ROW_NUMBER() OVER (PARTITION BY cwe_id ORDER BY cwss DESC) AS rn FROM result_vuln_scan_db WHERE scan_uuid = %s) r WHERE r.rn = 1 ORDER BY r.cwss DESC;"
        cursor.execute(select_query, (scan_uuid,))
        data = cursor.fetchall()
        cursor.close()
        import_module.close_connection(conn)

        if data:
            data_list = []
            for row in data:
                # Convert record to a dictionary for JSON response
                data_dict = {
                    'scan_uuid': row[0],
                    'severity': row[1],
                    'location': row[2],
                    'cwss': row[3],
                    'cwe_id': row[4],
                    'cwe_name': row[5],
                    'cwe_description': row[6],
                    'cwe_solution': row[7],
                    'count': row[10]
                }
                data_list.append(data_dict)
            return {'Scanned a machine': data_list}
        else:
            return f'{scan_uuid} not found'

    except Exception as e:
        return 'Error retrieving result: ' + str(e)
    
@app.route('/getvulnpathpattern', methods=['GET'])
def get_all_vuln_path_pattern():
    try:
        scan_uuid = request.json.get('scan_uuid')
        if not scan_uuid:
            return "scan_uuid is missing in the request body"
        cwe_id = request.json.get('cwe_id')
        if not cwe_id: 
            return "cwe_id is missing in the request body"

        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT file_location_path , keyword_pattern FROM result_vuln_scan_db WHERE scan_uuid = %s AND cwe_id = %s"
        cursor.execute(select_query, (scan_uuid, cwe_id,))
        data = cursor.fetchall()
        cursor.close()
        import_module.close_connection(conn)

        if data:
            # Convert record to a dictionary for JSON response
            data_list = []
            for data in data:
                data_dict = {
                    'file_location_path': data[0],
                    'keyword_pattern': data[1],
                }
                data_list.append(data_dict)
            
            return {'Results': data_list}
        else:
            return 'No results found'
        
    except Exception as e:
        return 'Error retrieving results: ' + str(e)
    
@app.route('/get_vuln_severity_count', methods=['GET'])
def get_high_severity_count():
    try:    
        scan_uuid = request.json.get('scan_uuid')
        if not scan_uuid:
            return "scan_uuid is missing in the request body"
        severity = request.json.get('severity')
        if not severity: 
            return "severity is missing in the request body"
        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT COUNT(DISTINCT cwe_id) FROM result_vuln_scan_db WHERE scan_uuid = %s AND severity = %s"
        cursor.execute(select_query, (scan_uuid, severity,))
        high_severity_count = cursor.fetchone()[0]
        cursor.close()
        import_module.close_connection(conn)
        return {'Results': high_severity_count}
    except Exception as e:
        return "Error retrieving high severity count: " + str(e)
    
@app.route('/get_total_vuln_cwss', methods=['GET'])
def get_total_vuln_cwss():
    try:    
        scan_uuid = request.json.get('scan_uuid')
        if not scan_uuid:
            return "scan_uuid is missing in the request body"
        # Perform the SELECT operation
        conn = import_module.connect()
        cursor = conn.cursor()
        select_query = "SELECT cwe_id, cwss FROM result_vuln_scan_db WHERE scan_uuid = %s GROUP BY cwe_id, cwss"
        cursor.execute(select_query, (scan_uuid, ))
        data = cursor.fetchall()
        cursor.close()
        import_module.close_connection(conn)

        if data:
            # Convert record to a dictionary for JSON response
            data_list = []
            for data in data:
                data_dict = {
                    'cwe_id': data[0],
                    'cwss': data[1],
                }
                data_list.append(data_dict)
            
            return data_list
        else:
            return 'No results found'
    except Exception as e:
        return "Error retrieving high severity count: " + str(e)

@app.route('/addvulndetected', methods=['POST'])
def insert_vuln_detected():
    try:
        # Retrieve data from the request
        scan_uuid = request.json['scan_uuid']
        severity = request.json['severity']
        location = request.json['location']
        cwss = request.json['cwss']
        cwe_id = request.json['cwe_id']
        cwe_name = request.json['cwe_name']
        cwe_description = request.json['cwe_description']
        cwe_solution = request.json['cwe_solution']
        file_location_path = request.json['file_location_path']
        keyword_pattern = request.json['keyword_pattern']
        count = request.json['count']

        # Perform the insert operation
        conn = import_module.connect()
        cursor = conn.cursor()
        insert_query = "INSERT INTO result_vuln_scan_db (scan_uuid, severity, location , cwss, cwe_id , cwe_name, cwe_description, cwe_solution , file_location_path , keyword_pattern, count ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(insert_query, (scan_uuid, severity, location , cwss, cwe_id , cwe_name, cwe_description, cwe_solution , file_location_path , keyword_pattern, count))
        conn.commit()
        cursor.close()
        import_module.close_connection(conn)

        return 'Record inserted successfully'
    
    except Exception as e:
        return 'Error inserting result: ' + str(e)
    
if __name__ == '__main__':
    print("being run")
    app.run(debug=True)