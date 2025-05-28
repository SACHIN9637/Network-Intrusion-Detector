import ollama
a = input("Ask a Question")
response = ollama.chat(model='llama3.2', messages=[
  {
    'role': 'user',
    'content': a,
  },
])
print(response['message']['content'])