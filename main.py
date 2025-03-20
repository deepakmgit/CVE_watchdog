from flask import Flask, jsonify, render_template, request
import mysql.connector
import requests
import datetime

app = Flask(__name__)

# MySQL Connection Details
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Deepak@26",
    "database": "cve_db"
}

# Base URL of NVD API
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Get DB Connection
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Fetch and Insert CVE Data into MySQL
def fetch_and_store_cves(start_index=0, results_per_page=100):
    url = f"{NVD_API_URL}?startIndex={start_index}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    data = response.json()

    print()

    if "vulnerabilities" not in data:
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    for item in data["vulnerabilities"]:
        cve_id = item["cve"]["id"]
        description = item["cve"]["descriptions"][0]["value"]
        base_score = (
            item["cve"].get("metrics", {})
            .get("cvssMetricV2", [{}])[0]
            .get("cvssData", {})
            .get("baseScore", 0.0)
        )
        last_modified_date = item["cve"]["lastModified"]

        # Insert data while avoiding duplicates
        query = """
        INSERT INTO cve (id, description, base_score, last_modified_date)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        description = VALUES(description),
        base_score = VALUES(base_score),
        last_modified_date = VALUES(last_modified_date);
        """
        cursor.execute(query, (cve_id, description, base_score, last_modified_date))

    conn.commit()
    conn.close()

# Periodic Sync to Fetch CVE Data (Run Manually or in a Cron Job)
@app.route('/cves/sync')
def sync_cves():
    fetch_and_store_cves()
    return {"message": "CVE data synchronized successfully"}

# List CVEs with Pagination and Display in HTML
@app.route('/cves/list')
def list_cves():
    page = int(request.args.get('page', 1))
    results_per_page = int(request.args.get('results_per_page', 10))
    offset = (page - 1) * results_per_page

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(f"SELECT * FROM cve LIMIT %s OFFSET %s", (results_per_page, offset))
    cves = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) as total FROM cve")
    total_records = cursor.fetchone()["total"]

    conn.close()
    return render_template("list.html", cves=cves, total_records=total_records)

# Get CVE Details by ID
@app.route('/cves/<cve_id>')
def get_cve(cve_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve WHERE id = %s", (cve_id,))
    cve = cursor.fetchone()
    conn.close()

    if not cve:
        return {"error": "CVE not found"}, 404

    return render_template("detail.html", cve=cve)

# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)
