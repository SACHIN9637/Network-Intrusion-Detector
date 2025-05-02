from flask import Flask, request, jsonify
import ollama

app = Flask(__name__)

@app.route('/')
def home():
    with open('templates/index.html', 'r') as file:
        return file.read()

@app.route('/chat', methods=['POST'])
def chat():
    try:
        user_message = request.json.get('message', '')
        response = ollama.chat(model='llama3.2', messages=[
            {
                'role': 'user',
                'content': user_message,
            },

        ])
        return jsonify({'response': response['message']['content']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)