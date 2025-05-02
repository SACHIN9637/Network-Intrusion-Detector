# AI-Powered Intrusion Detection System 🔒

This project presents an advanced Intrusion Detection System (IDS) enhanced with AI and NLP techniques. It uses Latent Dirichlet Allocation (LDA) for topic modeling on preprocessed network data, enabling efficient detection and categorization of potential threats. A chatbot interface is also included to allow users to interactively query insights and monitor system status in real-time.

## 🚀 Features
- LDA-based anomaly and topic detection
- Cleaned and filtered dataset handling
- Chatbot interface for user interaction
- Modular and easy-to-extend Python architecture

## 📂 Project Structure
- `Instrusion_Detection.ipynb`: Main analysis and model-building notebook
- `ids.py`: Core IDS logic
- `chatbot.py`: NLP-based chatbot system
- `app.py`: Flask-based web interface
- `LDA_model.pkl`: Trained model for detection
- `cleaned_dataset.csv` / `filtered_dataset.csv`: Preprocessed datasets

## 🧠 Technologies Used
- Python, Scikit-learn, Pandas
- NLP, LDA Topic Modeling
- Flask (for app interface)
- RAG-style response architecture

## 🛠️ Setup & Run
Clone the repository, install dependencies, and run:
```bash
pip install -r requirements.txt
python app.py
