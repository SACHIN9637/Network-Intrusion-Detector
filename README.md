# 🛡️ Intrusion Detection System (IDS) with Machine Learning

A web-based intelligent Intrusion Detection System that utilizes machine learning (LDA) to detect and visualize network anomalies in real-time. Designed for scalability and modular integration in enterprise networks.

## 📌 Project Overview

This system helps detect both known and unknown network intrusions using a machine learning model and provides a simple web interface for live interaction and analysis.

## 👨‍💻 Author

- **Name:** Sachin Ganesh Jadhav  
- **Email ID:** sachin.jadhav@mitaoe.ac.in

---

## 📁 Project Structure

```
IDS/
├── RAG_pipeline/
│   ├── app.py                # Flask backend
│   ├── chatbot.py            # NLP-based user assistant
│   ├── ids.py                # Core ML detection logic
│   ├── Instrusion_Detection.ipynb  # Model training notebook
│   ├── cleaned_dataset.csv   # Preprocessed network traffic data
│   ├── filtered_dataset.csv  # Filtered traffic for training
│   ├── LDA_model.pkl         # Trained ML model
│   └── templates/
│       └── index.html        # Frontend UI
```

---

## 🚀 Features

- 📊 **Anomaly Detection** using Latent Dirichlet Allocation (LDA)
- 🌐 **Web-based Interface** with Flask
- 📈 **Visualizations**: Confusion matrix, anomaly trends, feature distributions
- 🤖 **Chatbot Assistant** for help and queries
- 🔐 Designed for **enterprise-level scalability**

---

## 🧑‍💻 Tech Stack

- **Language**: Python 3.9
- **Libraries**: Flask, Scikit-learn, Pandas, NumPy
- **Tools**: Jupyter Notebook, VS Code
- **OS**: Windows 11 (Development), Ubuntu 20.04 (Testing)

---

## 🛠️ Setup & Installation

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd IDS/RAG_pipeline
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Visit `http://localhost:5000` in your browser.

---

## 📊 Performance Metrics

| Metric     | Score |
|------------|-------|
| Accuracy   | 92%   |
| Precision  | 89%   |
| Recall     | 85%   |
| F1-Score   | 87%   |

---

## 🖥️ Usage Guide

- **Homepage**: Upload CSV/JSON dataset and start detection.
- **Dashboard**: View confusion matrix, anomaly trends, severity tables.
- **Help**: Get chatbot assistance and FAQs.
- **Export**: Download reports as `.csv` or `.pdf`.

---

## 🔧 Maintenance

- Regular model updates with new datasets.
- Performance monitoring using tools like Prometheus or Grafana.
- Logging & Security enhancements.
- User feedback and documentation updates.

---

## 📚 References

- [Scikit-learn](https://scikit-learn.org)
- [Flask](https://flask.palletsprojects.com)
- [Python](https://docs.python.org/3/)
- [NumPy](https://numpy.org/doc/)
- [Pandas](https://pandas.pydata.org/)

---

## 📃 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
