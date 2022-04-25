import os
from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    print(session)
    user_id = session['user_id']
    holdings = db.execute(
        'SELECT symbol, name, SUM(shares) AS shares, price FROM users JOIN transactions ON users.id = transactions.user_id WHERE users.id = ? GROUP BY symbol HAVING SUM(shares) > 0',
        user_id)
    cash = db.execute('SELECT cash FROM users WHERE id = ?', user_id)[0]['cash']
    total = cash
    for holding in holdings:
        holding['price'] = lookup(holding['symbol'])['price'] * holding['shares']
        total = total + holding['price']

    return render_template('index.html', holdings=holdings, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == 'GET':
        return render_template('buy.html')

    user_id = session['user_id']
    symbol = request.form.get('symbol')
    shares = request.form.get('shares')

    # Ensure fields not blank
    if not (symbol and shares):
        return apology('missing values')

    # Ensure symbol is valid
    if lookup(symbol) == None:
        return apology('invalid symbol')

    # Ensure shares number is positive
    shares = int(shares)
    if shares <= 0:
        return apology('shares must be positive')

    # Ensure sufficient cash
    price = lookup(symbol)['price']
    cost = price * shares
    cash = db.execute('SELECT cash FROM users WHERE id = ?', user_id)[0]['cash']

    if cash < cost:
        return apology('insufficient cash')

    # Update DB to make purchase
    db.execute('INSERT INTO transactions (user_id, symbol, name, price, shares, datetime) VALUES (?, ?, ?, ?, ?, ?)',
               user_id, symbol, lookup(symbol)['name'], price, shares, datetime.now())
    db.execute('UPDATE users SET cash = ? WHERE id = ?', cash - cost, user_id)

    flash('Bought!')
    return redirect('/')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute(
        'SELECT symbol, shares, price, datetime FROM users JOIN transactions ON users.id = transactions.user_id WHERE users.id = ?',
        session['user_id'])
    return render_template('history.html', transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session['user_id'] = rows[0]["id"]

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
    flash('Logout successfull')
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template('quote.html')

    quotes = lookup(request.form.get('symbol'))
    if quotes == None:
        return apology('invalid symbol')
    else:
        return render_template('quoted.html', quotes=quotes)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get('username')
    password = request.form.get('password')
    confirmation = request.form.get('confirmation')

    # Ensure username is not blank
    if not (username and password and confirmation):
        return apology("missing value")

    # Ensure username is does not already exist
    if db.execute('SELECT username FROM users WHERE username = ?', username):
        return apology('username taken')

    # Ensure passwords match
    if password != confirmation:
        return apology('passwords must match')

    # If all well, register the user
    db.execute('INSERT INTO users (username, hash) VALUES (?, ?)', username, generate_password_hash(password))

    # Login the new user as well
    session.clear()
    session["user_id"] = db.execute("SELECT id FROM users WHERE username = ?", username)

    flash('Registration successfull')
    return redirect('/')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == 'GET':
        holdings = db.execute(
            'SELECT symbol FROM users JOIN transactions ON users.id = transactions.user_id WHERE users.id = ? GROUP BY symbol',
            session['user_id'])
        return render_template('sell.html', holdings=holdings)

    symbol = request.form.get('symbol')
    shares = int(request.form.get('shares'))

    # Ensure fields
    if not (symbol and shares):
        return apology('missing values')

    # Ensure positive shares
    shares = int(shares)
    if shares < 1:
        return apology('shares must be +ve')

    holdings = db.execute(
        'SELECT symbol, SUM(shares) AS shares, cash FROM users JOIN transactions ON users.id = transactions.user_id WHERE users.id = ? AND symbol = ? GROUP BY symbol',
        session['user_id'], symbol)

    # Ensure selected symbol in portfolio
    if holdings[0]['symbol'] == None:
        return apology('symbol not in portfolio')

    # Ensure number of shares of selected symbol in portfolio
    if shares > holdings[0]['shares']:
        return apology('symbol not in portfolio')

    price = lookup(holdings[0]['symbol'])['price']
    value = price * shares

    db.execute('INSERT INTO transactions (user_id, symbol, name, price, shares, datetime) VALUES (?, ?, ?, ?, ?, ?)',
               session['user_id'], symbol, lookup(symbol)['name'], price, -1 * shares, datetime.now())
    db.execute('UPDATE users SET cash = ? WHERE id = ?', holdings[0]['cash'] + value, session['user_id'])

    flash('Sold')
    return redirect('/')

# Query to create the SQLite table
# CREATE TABLE transactions (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, user_id INTEGER NOT NULL, symbol TEXT NOT NULL, name TEXT NOT NULL, price NUMERIC NOT NULL, shares INTEGER NOT NULL, datetime TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));