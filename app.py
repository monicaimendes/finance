import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/password", methods=["GET", "POST"])
def password():
    if request.method == "POST":
        new_password = request.form.get("new_password")
        username = request.form.get("username")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure actual password was submitted
        elif not request.form.get("password"):
            return apology("must provide actual password", 403)

        # Ensure new password was submitted
        elif not new_password:
            return apology("must provide new password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get(
                "username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or actual password", 403)

        password_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE username = ?;", password_hash, username)

        return render_template("login.html")

    return render_template("password.html")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_info = []

    symbols = db.execute(
        "SELECT quote_symbol AS symbol FROM transactions WHERE user_id = ? GROUP BY quote_symbol;", session["user_id"])

    cash = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])[0]["cash"]

    for symbol in symbols:
        bought_shares = db.execute("SELECT SUM(shares) AS shares FROM transactions WHERE quote_symbol = ? AND user_id = ? AND transaction_type = 'buy';", symbol.get(
            "symbol"), session["user_id"])[0]["shares"] or 0

        sold_shares = db.execute("SELECT SUM(shares) AS shares FROM transactions WHERE quote_symbol = ? AND user_id = ? AND transaction_type = 'sell';", symbol.get(
            "symbol"), session["user_id"])[0]["shares"] or 0

        owned_shares = bought_shares - sold_shares

        if owned_shares > 0:
            stock = lookup(symbol.get("symbol"))
            total_value = stock["price"] * owned_shares

            user_info.append({"symbol": symbol.get("symbol"), "shares": owned_shares,
                              "current_price": stock["price"], "total": total_value})

    grand_total = cash

    if user_info:
        for info in user_info:
            grand_total = grand_total + info.get("total")
            info["current_price"] = usd(info["current_price"])
            info["total"] = usd(info["total"])

    return render_template("index.html", user_info=user_info, cash=usd(cash), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock = lookup(symbol)
        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except:
            return apology("Fill in the shares correctly")

        if not symbol:
            return apology("Fill in a symbol")
        if not stock:
            return apology("Symbol does not exist")
        if shares < 1:
            return apology("Fill in the shares correctly")

        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        price_to_pay = shares * stock["price"]

        print(f"user_cash: {user_cash}")
        print(f"price_to_pay: {price_to_pay}")
        print(f"shares: {shares}")

        if user_cash < price_to_pay:
            return apology("You don't have enough cash")

        db.execute("INSERT INTO transactions (user_id, quote_name, quote_price, quote_symbol, shares, transaction_type) VALUES (?, ?, ?, ?, ?, ?);",
                   session["user_id"], stock["name"], stock["price"], stock["symbol"], shares, "buy")

        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   user_cash - price_to_pay, session["user_id"])

        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute(
        "SELECT date, quote_price, quote_symbol, shares, transaction_type FROM transactions WHERE user_id = ? ORDER BY date DESC;", session["user_id"])

    for transaction in transactions:
        transaction["quote_price"] = usd(transaction["quote_price"])

        if transaction["transaction_type"] == "buy":
            transaction["transaction_type"] = "bought"
        else:
            transaction["transaction_type"] = "sold"

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Fill in a symbol")

        quote = lookup(symbol)

        if not quote:
            return apology("Symbol does not exist.")

        return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Fill in the username.")

        if not password or not confirmation:
            return apology("Fill in the password and the confirmation.")

        if password != confirmation:
            return apology("Password and confirmation are different.")

        password_hash = generate_password_hash(password)

        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)
        except ValueError:
            return apology("Username already exists.")

        return redirect("/login")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        stock = lookup(symbol)

        if not symbol or not shares:
            return apology("Fill in all the fields")

        try:
            shares = int(shares)
        except:
            return apology("The shares must be a positive integer number")

        if shares < 1:
            return apology("The shares must be a positive integer number")

        bought_shares = db.execute(
            "SELECT SUM(shares) AS shares FROM transactions WHERE quote_symbol = ? AND user_id = ? AND transaction_type = 'buy';", symbol, session["user_id"])[0]["shares"] or 0

        sold_shares = db.execute("SELECT SUM(shares) AS shares FROM transactions WHERE quote_symbol = ? AND user_id = ? AND transaction_type = 'sell';",
                                 symbol, session["user_id"])[0]["shares"] or 0

        owned_shares = bought_shares - sold_shares

        if owned_shares < shares:
            return apology("You don't own enough shares")

        value_to_receive = stock["price"] * shares

        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        db.execute("INSERT INTO transactions (user_id, quote_name, quote_price, quote_symbol, shares, transaction_type) VALUES (?, ?, ?, ?, ?, ?);",
                   session["user_id"], stock["name"], stock["price"], stock["symbol"], shares, "sell")

        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   user_cash + value_to_receive, session["user_id"])

        return redirect("/")

    symbols = db.execute(
        "SELECT quote_symbol FROM transactions WHERE user_id = ? GROUP BY quote_symbol;", session["user_id"])

    return render_template("sell.html", symbols=symbols)
