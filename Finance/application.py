import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL(os.environ.get("DATABASE_URL"))

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute(
        "SELECT symbol, company_name, SUM(share_quantity) AS quantity, AVG(share_price) AS p FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING SUM(share_quantity) > 0", user_id=session["user_id"])
    total = 0.0
    for row in rows:
        temp = row['quantity'] * row['p']
        row['price'] = usd(row['p'])
        row['total_price'] = usd(temp)
        total += temp
    balance = float(db.execute(
        "SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])[0]['cash'])
    total += balance
    return render_template("index.html", rows=rows, balance=usd(balance), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("input is blank", 403)

        stock = lookup(request.form.get("symbol"))

        if stock == None:
            return apology("the symbol does not exist", 404)

        if not request.form.get("shares") or int(request.form.get("shares")) <= 0:
            return apology("shares can not be negative", 400)

        share_quantity = int(request.form.get("shares"))

        balance = float(db.execute(
            "SELECT cash from users WHERE id = :user_id", user_id=session["user_id"])[0]["cash"])
        share_price = float(stock["price"])

        if share_price * share_quantity > balance:
            return apology("Your current balance can not afford to buy current shares", 403)

        balance -= share_price * share_quantity

        db.execute("INSERT INTO transactions (user_id, symbol, company_name, share_quantity, share_price) \
        VALUES (:user_id, :symbol, :name, :quantity, :price)", user_id=session["user_id"], symbol=stock["symbol"], name=stock["name"], quantity=share_quantity, price=share_price)
        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
                   cash=balance, user_id=session["user_id"])

        flash(f"Buy {share_quantity} shares of {stock['symbol']} successfully")
        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute(
        "SELECT symbol, share_quantity, share_price, transacted FROM transactions WHERE user_id = :user_id", user_id=session["user_id"])
    for row in rows:
        row['price'] = usd(row['share_price'])
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        username = request.form.get("username")

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash(f"Hi {username}!!!")
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
        if not request.form.get("symbol"):
            return apology("input is blank", 403)
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return apology("the symbol does not exist", 403)
        return render_template("quoted.html", name=stock["name"], symbol=stock["symbol"], price=usd(stock["price"]))
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # check username is blank
        if not username:
            return apology("username can not be blank")

        # query database to see if username exists in db or not
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)

        # check if username exists
        if len(rows) > 0:
            return apology("the username already exists")

        # check password is blank or not
        elif not password:
            return apology("password can not be blank")

        # check if confirmation password equals to password
        elif password != request.form.get("confirmation"):
            return apology("the passwords do not match")

        # add user to users table
        user_id = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                             username=username, hash=generate_password_hash(password))

        session["user_id"] = user_id
        # return to login page
        flash(f"Hi {username}")
        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")

        if symbol.upper() == "SYMBOL" or not symbol:
            return apology("Missing symbol", 400)

        rows = db.execute("SELECT SUM(share_quantity) AS quantity FROM transactions WHERE user_id = :user_id AND symbol = :symbol",
                          user_id=session["user_id"], symbol=symbol)

        shares = request.form.get("shares")
        if not shares or int(shares) <= 0:
            return apology("shares can not be negative", 400)

        shares = int(shares)

        if shares > rows[0]["quantity"]:
            return apology("Too many shares", 400)

        share = lookup(request.form.get("symbol"))

        balance = float(db.execute(
            "SELECT cash from users WHERE id = :user_id", user_id=session["user_id"])[0]["cash"])

        balance += float(share['price']) * shares

        db.execute("INSERT INTO transactions (user_id, symbol, company_name, share_quantity, share_price) \
        VALUES (:user_id, :symbol, :name, :quantity, :price)", user_id=session["user_id"], symbol=symbol, name=share["name"], quantity=-shares, price=share['price'])

        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
                   cash=balance, user_id=session["user_id"])

        flash(f"Sell {shares} shares of {share['symbol']} successfully")
        return redirect("/")
    rows = db.execute(
        "SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING SUM(share_quantity) > 0", user_id=session["user_id"])
    return render_template("sell.html", rows=rows)


@ app.route('/forgot', methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return apology("Username can not be blank")

        rows = db.execute("SELECT username FROM users WHERE username = :username",
                          username=username)
        if not rows:
            return apology("Username not found")
        return render_template("reset.html", username=rows[0]['username'])
    return render_template("forgot.html")


@ app.route('/reset', methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        print(request.form.get("username"))
        rows = db.execute("SELECT id FROM users WHERE username = :username",
                          username=request.form.get("username"))

        if not rows:
            return apology("Username not found", 400)

        if not request.form.get("password"):
            return apology("password can not be blank", 403)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("the passwords do not match", 403)
        db.execute("UPDATE users SET hash = :pass_hash WHERE id = :user_id",
                   user_id=rows[0]['id'], pass_hash=generate_password_hash(request.form.get("password")))

        flash("Change password successful")
        return render_template("login.html")

    return apology("Forbidden", 403)


@ app.route('/add', methods=["GET", "POST"])
@ login_required
def add_cash():
    if request.method == "POST":
        if not request.form.get("cash"):
            return apology("Cash input can not be blank", 400)

        cash = float(request.form.get("cash"))
        if cash < 1000:
            return apology("Minimum cash required is 1000", 400)

        balance = float(db.execute(
            "SELECT cash from users WHERE id = :user_id", user_id=session["user_id"])[0]["cash"])

        db.execute("UPDATE users SET cash = :balance WHERE id = :user_id",
                   balance=balance + cash, user_id=session["user_id"])

        flash(f"add {usd(cash)} to account successfully")
        return redirect('/')

    return render_template("add.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == "main":
    app.debug = True
    port = int(os.environ.get("PORT", 5000))
    print(port)
    app.run(host='0.0.0.0', port=port)
