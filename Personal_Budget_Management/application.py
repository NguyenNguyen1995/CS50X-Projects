import os

from cs50 import SQL
from flask import Flask, flash, render_template, session, request, redirect, url_for
from flask_session import Session
from flask.json import jsonify
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from helpers import login_required, apology, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure CS50 Library to use database
db = SQL(os.environ.get("DATABASE_URL"))

# Custom filter
app.jinja_env.filters["usd"] = usd
app.secret_key = os.environ.get("SECRET_KEY")

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.route("/")
@login_required
def index():
    return render_template("home/index.html")


@app.route("/summary")
@login_required
def summary():
    incomes = db.execute(
        "SELECT SUM(cash) AS total_income FROM income WHERE user_id = :user_id", user_id=session["user_id"])
    spendings = db.execute(
        "SELECT SUM(cash) AS total_spending FROM spending WHERE user_id = :user_id", user_id=session["user_id"])
    # if incomes[0]['total_income'] == None:
    #     incomes[0]['total_income'] = 0
    # if spendings[0]['total_spending'] == None:
    #     spendings[0]['total_spending'] = 0
    return jsonify(incomes + spendings)


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
        return render_template("auth/login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # check username is blank
        if not request.form.get("username"):
            return apology("username can not be blank", 403)

        # query database to see if username exists in db or not
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # check if username exists
        if len(rows) > 0:
            return apology("the username already exists", 403)

        # check password is blank or not
        elif not request.form.get("password"):
            return apology("password can not be blank", 403)

        # check if confirmation password equals to password
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("the passwords do not match", 403)

        # add user to users table
        user_id = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=request.form.get(
            "username"), hash=generate_password_hash(request.form.get("password")))

        session["user_id"] = user_id
        # return to login page
        flash("Sign up successfully\n")
        username = request.form.get('username')
        flash(f"Hi {username}")
        return redirect("/")

    return render_template("auth/signup.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/income")
@login_required
def income():
    incomes = db.execute(
        "SELECT i.id, i.name, c.name AS type, i.cash FROM income AS i INNER JOIN categories_income AS c ON i.categories_id = c.id WHERE i.user_id = :user_id", user_id=session["user_id"])
    return render_template("income/index.html", incomes=incomes)


@app.route("/add-income", methods=["GET", "POST"])
@login_required
def add_income():
    if request.method == "POST":
        name = request.form.get('name')
        cate_name = request.form.get('categories')
        if not name:
            return apology('Name can not be blanked')
        if not cate_name:
            return apology('Category type can not be default')

        c_id = db.execute('SELECT id FROM categories_income WHERE name = :name',
                          name=cate_name)
        if not request.form.get('cash'):
            return apology('Cash can not be blanked')
        cash = int(request.form.get('cash'))
        if cash <= 0:
            return apology('Cash can not be negative')
        print(c_id[0]['id'])
        isSuccess = db.execute(
            'INSERT INTO income (name, categories_id, user_id, cash) VALUES (:name, :c_id, :u_id, :cash)', name=name.capitalize(), c_id=c_id[0]["id"], u_id=session["user_id"], cash=cash)
        if not isSuccess:
            return apology("Can not add income to budget. Error!!")
        flash("Add successful")
        return redirect('/income')
    income_types = db.execute("SELECT name FROM categories_income")
    return render_template("income/add.html", income_types=income_types)


@app.route("/edit-income/<id>", methods=["GET", "POST"])
@login_required
def edit_income(id):
    if request.method == "POST":
        name = request.form.get('name')
        cate_name = request.form.get('categories')
        if not name:
            return apology('Name can not be blanked')
        if not cate_name:
            return apology('Category type can not be default')

        c_id = db.execute('SELECT id FROM categories_income WHERE name = :name',
                          name=cate_name)[0]['id']
        if not request.form.get('cash'):
            return apology('Cash can not be blanked')
        cash = int(request.form.get('cash'))
        if cash <= 0:
            return apology('Cash can not be negative')
        isSuccess = db.execute(
            'UPDATE income SET name = :name, categories_id = :c_id, cash = :cash WhERE user_id = :u_id AND id=:id', id=int(id), name=name, c_id=c_id, u_id=session["user_id"], cash=cash)
        if not isSuccess:
            return apology("Can not edit record to budget. Error!!")
        flash("Edit successful")
        return redirect('/income')
    income = db.execute(
        "SELECT id, name, categories_id, cash FROM income WHERE user_id = :u_id AND id = :id", u_id=session["user_id"], id=id)
    i_types = db.execute('SELECT * FROM categories_income')
    return render_template('income/edit.html', income=income[0], i_types=i_types)


@app.route("/delete-income/<id>")
@login_required
def delete_income(id):
    isSuccess = db.execute('DELETE FROM income WHERE id = :id', id=id)
    if isSuccess:
        flash("Delete successful")
        return redirect('/income')
    return apology("Can not delete income record from budget. Error!!")


@app.route("/spending")
@login_required
def spending():
    spendings = db.execute(
        "SELECT s.id, s.name, c.name AS type, s.cash FROM spending AS s INNER JOIN categories_spending AS c ON s.categories_id = c.id WHERE s.user_id = :user_id", user_id=session["user_id"])
    return render_template("spending/index.html", spendings=spendings)


@app.route("/add-spending", methods=["GET", "POST"])
@login_required
def add_spending():
    if request.method == "POST":
        name = request.form.get('name')
        cate_name = request.form.get('categories')
        if not name:
            return apology('Name can not be blanked')
        if not cate_name:
            return apology('Category type can not be default')

        c_id = db.execute('SELECT id FROM categories_spending WHERE name = :name',
                          name=cate_name)
        if not request.form.get('cash'):
            return apology('Cash can not be blanked')
        cash = int(request.form.get('cash'))
        if cash <= 0:
            return apology('Cash can not be negative')
        isSuccess = db.execute(
            'INSERT INTO spending (name, categories_id, user_id, cash) VALUES (:name, :c_id, :u_id, :cash)', name=name.capitalize(), c_id=c_id[0]["id"], u_id=session["user_id"], cash=-cash)

        if not isSuccess:
            return apology("Can not add spending to budget. Error!!")
        flash("Add successful")
        return redirect('/spending')
    spending_types = db.execute("SELECT name FROM categories_spending")
    return render_template("spending/add.html", spending_types=spending_types)


@app.route("/edit-spending/<id>", methods=["GET", "POST"])
@login_required
def edit_spending(id):
    if request.method == "POST":
        name = request.form.get('name')
        cate_name = request.form.get('categories')
        if not name:
            return apology('Name can not be blanked')
        if not cate_name:
            return apology('Category type can not be default')

        c_id = db.execute('SELECT id FROM categories_spending WHERE name = :name',
                          name=cate_name)[0]['id']
        if not request.form.get('cash'):
            return apology('Cash can not be blanked')
        cash = int(request.form.get('cash'))
        if cash <= 0:
            return apology('Cash can not be negative')
        isSuccess = db.execute(
            'UPDATE spending SET name = :name, categories_id = :c_id, cash = :cash WhERE user_id = :u_id AND id=:id', id=int(id), name=name, c_id=c_id, u_id=session["user_id"], cash=-cash)
        if not isSuccess:
            return apology("Can not edit record to budget. Error!!")
        flash("Edit successful")
        return redirect('/spending')
    spending = db.execute(
        "SELECT id, name, categories_id, cash FROM spending WHERE user_id = :u_id AND id = :id", u_id=session["user_id"], id=id)
    i_types = db.execute('SELECT * FROM categories_spending')
    return render_template('spending/edit.html', spending=spending[0], i_types=i_types)


@app.route("/delete-spending/<id>")
@login_required
def delete_spending(id):
    isSuccess = db.execute('DELETE FROM spending WHERE id = :id', id=id)
    if isSuccess:
        flash("Delete successful")
        return redirect('/spending')
    return apology("Can not delete spending record from budget. Error!!")


@app.route("/history")
@login_required
def history():
    incomes = db.execute(
        "SELECT 'Income' AS kind, i.name, c.name AS type, i.cash, i.created FROM income AS i INNER JOIN categories_income AS c ON i.categories_id = c.id WHERE i.user_id = :user_id", user_id=session["user_id"])
    spendings = db.execute(
        "SELECT 'Spending' AS kind, s.name, c.name AS type, s.cash, s.created FROM spending AS s INNER JOIN categories_spending AS c ON s.categories_id = c.id WHERE s.user_id = :user_id", user_id=session["user_id"])
    return render_template('history.html', rows=incomes+spendings)


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
        return render_template("auth/login.html")

    return apology("Forbidden", 403)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
