# 💲Finance

## 📌 Description
This is a Flask project that simulates buying, selling, and tracking the transaction history of shares in the American stock market.
It consumes the finance API from Harvard's CS50 course.

## 🛠️ Prerequisites
Before getting started, you need to have installed:
- [Python](https://www.python.org/) (version 3.8+)
- [Pip](https://pip.pypa.io/en/stable/)

## 🔧 Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/monicaimendes/finance.git
   cd finance
   ```
2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv env
   source env/bin/activate  # Linux/macOS
   env\Scripts\activate     # Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## ▶️ How to Run
1. Run the application:
   ```bash
   flask run
   ```
2. Access in your browser:
   ```
   http://127.0.0.1:5000
   ```

## 📁 Project Structure
```
/finance
│── app.py            # Main Flask file
│── finance.db        # Database (SQLite)
│── requirements.txt  # Project dependencies
│── helpers.py        
│── static/           # Static files (CSS, JS, images)
│── templates/        # HTML templates
│── README.md         # This file :)
│── .gitignore        # Git ignored files
```
