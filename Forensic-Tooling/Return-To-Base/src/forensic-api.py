
from flask import Flask, request, jsonify
import traceback

app = Flask(__name__)

@app.route('/upload_forensic_data', methods=['POST'])
def upload_forensic_data():
    try:
        data = request.get_json()
        print("✅ Received Data:", data)  # Debugging print statement
        return jsonify({"message": "Log received", "status": "success"}), 200
    except Exception as e:
        print("❌ ERROR:", str(e))
        print(traceback.format_exc())  # Print full error traceback
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)  # Enable Debug Mode
