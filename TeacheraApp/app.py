"""The Flask app, with initialization and view functions."""

import logging
import base64
import datetime
from functools import wraps
from unicodedata import normalize
from sqlalchemy import func

from flask import send_from_directory
from flask import abort, jsonify, redirect, render_template, request, url_for, flash, session, make_response
from flask.ext.login import LoginManager, current_user, login_user
from flask.ext.login import login_user, login_required, logout_user
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import Security, SQLAlchemyUserDatastore
from flask.ext.security.signals import user_registered
from flask.ext.security.utils import url_for_security
from flask.ext.admin import Admin, BaseView, expose, AdminIndexView
from flask.ext.admin.contrib.sqla import ModelView
#from flask.ext.misaka import Misaka
from flask_oauthlib.client import OAuth , OAuthException
from flask_mail import Mail, Message


from werkzeug import secure_filename
from wtforms.ext.appengine import db

from config import DefaultConfig
import filters
from forms import ResumeForm, CourseForm, ExtendedRegisterForm, RegisterCoachForm, ContactForm
from models import User, Resume, Course, Role, Oauth, CoachUserData, ResumeView
from common import app, db, security
#from teacheraApp.pdfs import create_pdf
from utils.base62 import dehydrate, saturate

import stripe

def slug(text, encoding=None,permitted_chars='abcdefghijklmnopqrstuvwxyz0123456789-'):
    if isinstance(text, str):
        text = text.decode(encoding or 'ascii')
    clean_text = text.strip().replace(' ', '-').lower()
    while '--' in clean_text:
        clean_text = clean_text.replace('--', '-')
    ascii_text = normalize('NFKD', clean_text).encode('ascii', 'ignore')
    strict_text = map(lambda x: x if x in permitted_chars else '', ascii_text)
    return ''.join(strict_text)

app.config.from_object(DefaultConfig)
stripe.api_key = app.config.get('STRIPE_SECRET_KEY')


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security.init_app(app, user_datastore, register_form=ExtendedRegisterForm)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.has_role('ROLE_ADMIN') is False:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

def coach_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.has_role('ROLE_COACH') is False:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.has_role('ROLE_STUDENT') is False:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

class MyAdminIndexView(AdminIndexView):
    @login_required
    @admin_required
    @expose('/')
    def index(self):
        return self.render('admin/index.html')

class AdminView(ModelView):
    column_searchable_list = (User.name, User.email)
    column_exclude_list = ('created', 'modified','password', 'active', 'confirmed_at','coach')
    def is_accessible(self):
        return current_user.has_role('ROLE_ADMIN')

# Flask-Admin
admin = Admin(app, name='Teachera', index_view=MyAdminIndexView())

admin.add_view(AdminView(User, db.session))
admin.add_view(AdminView(Resume, db.session))
admin.add_view(AdminView(Course, db.session))
admin.add_view(AdminView(CoachUserData, db.session))


@user_registered.connect_via(app)
def user_registered_sighandler(app, user, confirm_token):
    default_role = user_datastore.find_role("ROLE_STUDENT")
    user_datastore.add_role_to_user(user, default_role)
    db.session.commit()


@app.before_first_request
def create_user():
    db.create_all()
    if not User.query.first():
        user_datastore.create_user(username='admin', email='admin@example.com',
                             password='admin', roles=['admin'])
        db.session.commit()
# Load custom Jinja filters from the `filters` module.
filters.init_app(app)

def date_from_string(date):
    if date:
      return date if len(date)>0 else '-'
    else:
      return '-'

def base64_encode(value):
    return base64.b64encode(str(value))

app.jinja_env.filters['datefromstring'] = date_from_string
app.jinja_env.filters['b64'] = base64_encode
app.jinja_env.filters['b62'] = dehydrate
app.jinja_env.filters['slug'] = slug

#Misaka(app)
mail = Mail(app)

# Setup logging for production.
if not app.debug:
    app.logger.setHandler(logging.StreamHandler()) # Log to stderr.
    app.logger.setLevel(logging.INFO)


@app.errorhandler(404)
def error_not_found(error):
    """Render a custom template when responding with 404 Not Found."""
    return render_template('error/not_found.html'), 404


########################OAUTH#################################################
oauth = OAuth(app)

facebook = oauth.remote_app(
    'facebook',
    consumer_key=app.config['FACEBOOK_LOGIN_APP_ID'],
    consumer_secret=app.config['FACEBOOK_LOGIN_APP_SECRET'],
    request_token_params={'scope': 'email'},
    base_url='https://graph.facebook.com',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    access_token_method='POST',
)


@app.route('/login/fb')
def login_fb():
    callback = url_for(
        'facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True
    )
    return facebook.authorize(callback=callback)



@app.route('/login/fb/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None: # Authentication failure...
        flash("There was a problem with log in using Facebook: {0}".format(request.args['error_description']), 'danger')
        return render_template('landing.html')

    # Facebook session token
    session['oauth_token'] = (resp['access_token'], '')
    # Load facebook profile
    profile = facebook.get('/me')

    # Try to find user and his Oauth record in db
    user = db.session.query(User).filter(User.email==profile.data['email']).first()
    oauth = db.session.query(Oauth).filter(Oauth.provider_id==profile.data['id']).\
        filter(Oauth.provider=='facebook').first()

    # User not exist? So we need to 'register' him on the site
    if user is None:
        user = User()
        user.email = profile.data['email']
        user.name = profile.data['first_name'] + u" " + profile.data['last_name']
        user.password = unicode(u"fb-id|"+profile.data['id'])   # User from OAuth have no password (we save id)
        user.active = True
        user.confirmed_at = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        default_role = user_datastore.find_role("ROLE_STUDENT")
        user_datastore.add_role_to_user(user, default_role)
        db.session.commit()

    # Save some data from OAuth service that might be useful sometime later
    # This is also used when user was registered by e-mail and now he
    # logs in using social account for the same e-mail
    if oauth is None:
        oauth = Oauth()
        oauth.provider='facebook'
        oauth.provider_id=profile.data['id']
        oauth.email=profile.data['email']
        oauth.profile=profile.data['link']
        oauth.user=user     # Contect with user
        # There are few fields empty...
        db.session.add(oauth)
        db.session.commit()

    # Try to login new user
    lok = login_user(user)
    if lok:
        # Show green mesaage that all went fine
        flash("You have been successfully signed in using Facebook.", 'success')
        return redirect(url_for('resumes_list'))
    else:
        flash("There was a problem with your logining-in", 'warning')
        return render_template('landing.html')



# Here goes special functions need by Flask-OAuthlib
@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')


########################OAUTH#################################################

#######View for site map############
@app.route('/sitemap.xml')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route('/BingSiteAuth.xml')
def static_from_root_bing():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route('/sitemap')
def sitemap_html():
    return render_template('sitemap.html')

#########Views for Resume or Profiles#######


@app.route('/dashboard/')
def resumes_list():
    """Provide HTML page listing all resumes in the database."""
    # Query: Get all Resume (Profile) objects, sorted by the resume date.
    #appts = list()
    appts = db.session.query(Resume).filter_by(user_id=current_user.id)
             #.order_by(Resume.created.asc()).first())

    #for resume in resumes:
        ##views_count_resume = db.session.query(ResumeView.id).filter(ResumeView.resume == resume).count()
        ##appts.append((resume, views_count_resume))

    courses = db.session.query(Course).filter(
                Course.users.contains(current_user)).all()

    return render_template('resume/dashboard.html', appts=appts, courses=courses)

@app.route('/attendee/profile/view/<resume_id>/')
@login_required
#@coach_required
def resume_preview(resume_id):
    """Provide HTML page with all details on a given resume.
       The url is base64 encoded so no one will try to check other resumes.
    """
    resume_id = base64.b64decode(resume_id)
    appt = db.session.query(Resume).get(resume_id)
    if appt is None:
        # Abort with Not Found.
        abort(404)
    # Count the view to user resume views
    resume_view = ResumeView(current_user, appt)
    db.session.add(resume_view)
    db.session.commit()
    # Template without edit buttons
    return render_template('resume/resume_detail_preview.html', appt=appt)


@app.route('/profiles/<int:resume_id>/')
@login_required
def resume_detail(resume_id):
    """Provide HTML page with all details on a given resume."""
    # Query: get Resume object by ID.
    appt = db.session.query(Resume).get(resume_id)
    if appt is None or appt.user_id != current_user.id:
        # Abort with Not Found.
        abort(404)
    return render_template('resume/resume_detail.html', appt=appt)

@app.route('/profiles/create/', methods=['GET', 'POST'])
#@student_required
@login_required
def resume_create():
    """Provide HTML form to create a new resume record."""
    form = ResumeForm(request.form)
    if request.method == 'POST' and form.validate():
        appt = Resume(user_id=current_user.id)
        form.populate_obj(appt)
        db.session.add(appt)
        db.session.commit()
        # Success. Send the user back to the full resumes list.
        return redirect(url_for('resumes_list'))
    # Either first load or validation error at this point.
    return render_template('resume/edit.html', form=form)



@app.route('/profiles/<int:resume_id>/edit/', methods=['GET', 'POST'])
@login_required
def resume_edit(resume_id):
    """Provide HTML form to edit a given appointment."""
    appt = db.session.query(Resume).get(resume_id)
    if appt is None:
        abort(404)
    if appt.user_id != current_user.id:
        abort(403)
    form = ResumeForm(request.form, appt)
    if request.method == 'POST' and form.validate():
        form.populate_obj(appt)
        db.session.commit()
        # Success. Send the user back to the detail view of that resume.
        return redirect(url_for('resume_detail', resume_id=appt.id))
    return render_template('resume/edit.html', form=form)


@app.route('/profiles/<int:resume_id>/delete/', methods=['GET', 'POST'])
@login_required
def resume_delete(resume_id):
    appt = db.session.query(Resume).get(resume_id)
    if appt is None:
        abort(404)
    if appt.user_id != current_user.id:
        abort(403)

    resume_views = db.session.query(ResumeView).filter(ResumeView.resume == appt)
    for record in resume_views:
        db.session.delete(record)
    db.session.commit()

    db.session.delete(appt)
    db.session.commit()
    return redirect(url_for('resumes_list'))


#########Views for Courses#######

@app.route('/private/group/courses/<course_title>/<int:course_id>/apply/')
@login_required
def course_apply(course_id, course_title):
    """
    Applying for courses by applicants.

    THIS VIEW IS FOR APPLICANTS
    :param course_id: id of course to apply/join
    :return: nothing
    """
    course = db.session.query(Course).get(course_id)
    if course is None:
        abort(404)
    elif current_user.id is None:
        abort(403)
    else:
        if current_user in course.users:
            flash("You have <strong>already applied</strong> for {0}.".format(course.course_title), 'warning')
            return redirect(url_for('course_list'))
        else:
            rent_per_hour_count = course.rent_per_hour / course.min_students
            amount = 0

            amount1 = course.cost_per_hour * 0.5 + course.cost_per_hour * course.hours_per_month / course.min_students + rent_per_hour_count
            amount2 = course.cost_per_hour * 0.4 + course.cost_per_hour * course.hours_per_month / course.min_students + rent_per_hour_count
            amount3 = course.cost_per_hour * 0.6 + course.cost_per_hour * course.hours_per_month  / course.min_students + rent_per_hour_count
            if course.min_students == len(course.users):
                amount = amount1
            elif course.min_students > len(course.users):
                amount = amount2
            elif course.min_students < len(course.users):
                amount = amount3

            return render_template('course/payment.html', course=course, amount=amount,
                                   key=app.config.get('STRIPE_PUBLISHABLE_KEY'))


@app.route('/private/group/courses/<course_title>/<int:course_id>/charge', methods=['POST'])
@login_required
def charge(course_id, course_title):
    course = db.session.query(Course).get(course_id)
    rent_per_hour_count = course.rent_per_hour / course.min_students
    amount = 0

    amount1 = course.cost_per_hour * 0.5 + course.cost_per_hour * course.hours_per_month / course.min_students + rent_per_hour_count
    amount2 = course.cost_per_hour * 0.4 + course.cost_per_hour * course.hours_per_month / course.min_students + rent_per_hour_count
    amount3 = course.cost_per_hour * 0.6 + course.cost_per_hour * course.hours_per_month  / course.min_students + rent_per_hour_count

    if course.min_students == len(course.users):
        amount = amount1
    elif course.min_students > len(course.users):
        amount = amount2
    elif course.min_students < len(course.users):
        amount = amount3
    amount = amount * 100  # calculate the amount
    customer = stripe.Customer.create(
        email=current_user.email,
        card=request.form['stripeToken']
    )

    charge = stripe.Charge.create(
        customer=customer.id,
        amount=int(amount),
        currency='eur',
        description='EUR {amount} Payment for {course_name}'.format(amount=amount, course_name=course.course_title)
    )
    if charge.to_dict()['status'] == "succeeded":
        course.users.append(current_user)
        db.session.add(course)
        db.session.commit()
        flash("You have <strong>successfully applied</strong> for {0}.".format(course.course_title), 'success')
    else:
        flash("Some error occured. Please try again", 'warning')
    return redirect(url_for('course_list'))


@app.route('/courses/<int:course_id>/<course_title>/<city>')
def course_details(course_id , course_title , city):
    """Provide HTML page with all details on a given course.

    THIS VIEW IS FOR APPLICANTS
    """
    # Query: get Course object by ID.
    appt = db.session.query(Course).get(course_id)
    if current_user.is_anonymous:
        resume_exists = False
        anonymous = True
    else:
        resume_exists = bool(db.session.query(Resume).filter(Resume.user_id==current_user.id).count()> 0)
        anonymous = False
    return render_template('course/details.html', appt=appt,
                           have_resume=resume_exists, anonym=anonymous)

@app.route('/join-now/<b62id>/<course_title>')
def course_apply_now(b62id, course_title, city):
    course_id = saturate(b62id)
    return redirect(url_for('course_details', course_id=course_id, city=city, course_title=course_title))

# Coach views # Teachers #Tutors #Instructors

@app.route('/coach/signup/', methods=['GET', 'POST'])
def security_coach_register():
    return redirect(url_for_security('register', next=url_for('coach_register')))




@app.route('/coach/activate/', methods=['GET', 'POST'])
@login_required
def coach_register():
    coach_details = None
    try:
        coach_details = db.session.query(CoachUserData
                        ).filter_by(user_id=current_user.id).all()[0]
    except IndexError:
        pass

    if coach_details:
        return redirect(url_for('course_create'))

    form = RegisterCoachForm(request.form)
    if request.method == 'POST' and form.validate():
        appt = CoachUserData(user_id=current_user.id)
        #if not appt.last_name:
            #appt.last_name = ""
        form.populate_obj(appt)
        db.session.add(appt)

        coach_role = user_datastore.find_role("ROLE_COACH")
        user_datastore.add_role_to_user(current_user, coach_role)
        db.session.commit()

        # Success. Send to the postion list
        flash("Welcome to the dashboard for tutors or teachers and coaches.", 'succes')
        return redirect(url_for('course_create'))
    # Either first load or validation error at this point.
    return render_template('course/edit_coach.html', form=form)



@app.route('/courses/')
@login_required
#@coach_required
def course_list():
    """Provide HTML page listing all courses in the database.

    THIS VIEW IS FOR COMPANIES
    """
    # Query: Get all Course objects, sorted by the position date.
    if current_user and current_user.has_role('ROLE_COACH') == False:
        appts = (db.session.query(Course).
                 order_by(Course.course_start_date.asc()).all())
        return render_template('course/allcourse.html', appts=appts)

    else:
        appts = (db.session.query(Course)
             .filter_by(user_id=current_user.id)
             .order_by(Course.course_start_date.asc()).all())

    return render_template('course/index.html', appts=appts)

@app.route('/courses/create/', methods=['GET', 'POST'])
@login_required
#@coach_required
def course_create():
    """Provide HTML form to create a new courses record.

    THIS VIEW IS FOR COACHES
    """
    try:
        coach_details = db.session.query(CoachUserData
                        ).filter_by(user_id=current_user.id).all()[0]
    except IndexError:
        return redirect(url_for('coach_register'))

    if coach_details is None:
        return redirect(url_for('coach_register'))

    form = CourseForm(request.form)
    if coach_details is not None:
        form.coach_name.data = coach_details.coach_name
        #form.coach_website.data = coach_details.website

    if request.method == 'POST' and form.validate():
        appt = Course(user_id=current_user.id)
        form.populate_obj(appt)
        db.session.add(appt)
        db.session.commit()
        # Success. Send the user back to the full resumes list.
        return redirect(url_for('course_list'))
    # Either first load or validation error at this point.
    return render_template('course/edit.html', form=form)

@app.route('/coach/courses/<int:course_id>/edit/', methods=['GET', 'POST'])
@login_required
#@coach_required
def course_edit(course_id):
    """Provide HTML form to edit a given course.

    THIS VIEW IS FOR COACHES
    """
    appt = db.session.query(Course).get(course_id)
    if appt is None:
        abort(404)
    if appt.user_id != current_user.id and (not current_user.has_role('ROLE_ADMIN')):
        abort(403)
    form = CourseForm(request.form, appt)
    if request.method == 'POST' and form.validate():
        form.populate_obj(appt)
        #del form.created
        db.session.commit()
        # Success. Send the user back to the detail view of that resume.
        return redirect(url_for('course_details', course_id=appt.id, course_title=appt.course_title, city=appt.city))
    return render_template('course/edit.html', form=form)

@app.route('/coach/courses/<int:course_id>/delete/', methods=['GET', 'POST'])
@login_required
@coach_required
def course_delete(course_id):
    """Delete a record

    THIS VIEW IS FOR COACHES
    """
    appt = db.session.query(Course).get(course_id)

    if appt is None:
        # Abort with simple response indicating course not found.
        flash("Wrong Course id.", 'danger')
        return redirect(url_for('course_list'))
    if appt.user_id != current_user.id and (not current_user.has_role('ROLE_ADMIN')):
        # Abort with simple response indicating forbidden.
        flash("You can't remove this course.", 'danger')
        return redirect(url_for('course_list'))
    db.session.delete(appt)
    db.session.commit()
    flash("Course was removed.", 'success')
    return redirect(url_for('course_list'))
    # return jsonify({'status': 'OK'})

@app.route('/coach/courses/<int:course_id>/attendees/')
@login_required
#@coach_required
def course_list_applicants(course_id):

    course = db.session.query(Course).get(course_id)
    if course is None:
        abort(404)
    elif current_user.id is None:
        abort(403)
    #elif course.user_id != current_user.id and (not current_user.has_role('ROLE_ADMIN')):
        #abort(403)
    else:
        applicants_resumes = {}
        applicants = course.users
        for applicant in applicants:
            resumes = db.session.query(Resume).filter(Resume.user_id==applicant.id).all()
            if len(resumes) > 0:
                # encoding each id of resume
                resumes = [base64.b64encode(str(resume.id)) for resume in resumes ]
                applicants_resumes[applicant.id] = resumes
            else:
                applicants_resumes[applicant.id] = None
        return render_template('course/applicants.html', course_id=course_id,
                               applicants=applicants, resumes=applicants_resumes)


@app.route('/coach/courses/<int:course_id>/applicants/send-message/', methods=['GET', 'POST'])
@login_required
@admin_required
def course_applicants_send_email(course_id):
    """
     View for conntacitng all aplicants of postion by e-mail.

    :param course_id: id of postion that applicants will be contacted
    :return: None
    """
    if current_user.id is None:
        abort(403)
    else:
        form = ContactForm(request.form)
        if request.method == 'POST' and form.validate():
            course = db.session.query(Course).get(course_id)
            if course is None:
                abort(404)
            emails = [u.email for u in course.users]
            message = Message(subject=form.subject.data,
                            sender='info@teachera.org',
                           reply_to='info@teachera.org',
                           recipients=['info@teachera.org'],
                           bcc=emails,
                           body=form.text.data)
            mail.send(message)
            flash("Message was send.", 'succes')
            return redirect(url_for('course_list_applicants', course_id=course_id))
        return render_template('course/message_send_form.html', form=form)

###Public Views


def landing_page():
    if current_user.is_authenticated:
        if current_user.coach:
            return redirect(url_for('coach_register'))
        else:
            return redirect(url_for('resumes_list'))
    else:
        return render_template('landing.html')

@app.route('/')
@app.route('/students')
def landing_page_students():

    if current_user.is_authenticated:
        if current_user.coach:
            return redirect(url_for('coach_register'))
        else:
            return redirect(url_for('resumes_list'))
    else:
        appts = (db.session.query(Course).order_by(Course.course_start_date.asc()).all())
        
        return render_template('landing_page_students.html', appts=appts)


@app.route('/coach')
@app.route('/tutors/')
@app.route('/teachers')
@app.route('/teachers/tutors/coach')
def landing_page_teachers():
    if current_user.is_authenticated:
        if current_user.coach:
            return redirect(url_for('coach_register'))
        else:
            return redirect(url_for('resumes_list'))
    else:
        return render_template('landing_teachers.html')

@app.route('/about')
def about_us():
    return render_template('public/about.html')
@app.route('/faq')
def faq():
    return render_template('public/faq.html')

#@app.route('/policy')
def data_policy():
    return render_template('public/policy.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact_form():
    form = ContactForm(request.form)
    if request.method == 'POST' and form.validate():
        #SEND E-MAIL
        message = Message(subject=form.subject.data,
                        sender='support@teachera.org',
                       reply_to=current_user.email,
                       recipients=['support@teachera.org'],
                       body=form.text.data)
        mail.send(message)

        # Success. Send to the postion list
        flash("Your message was send.", 'succes')
        return redirect(url_for('resumes_list'))

    # Either first load or validation error at this point.
    return render_template('public/contact_form.html', form=form)

@app.route('/list/courses/')
def courses_list():
    
    appts = (db.session.query(Course).
             order_by(Course.course_start_date.asc()).all())
    return render_template('course/allcourse.html', appts=appts)




@app.route('/some-endpoint', methods=['POST'])
def share_email():
    share_text = "Your friend {0} on http://teachera.org want to recommend you this open course: {1}.\n"\
                  "Register, and view it here: {2}."\
                  "\n\n"\
                  "Regards,\n"\
                  "Teachera.org team"

    formated_text = share_text.format(current_user.name, request.form['title'], request.form['url'])
    message = Message(subject="Teachera.org - private classes recomendations!",
                       sender='info@teachera.org',
                       reply_to=current_user.email,
                       recipients=[request.form['email']],
                       body=formated_text)
    mail.send(message)




    print request.__dict__
    print request.form
    return jsonify(status='success')



#####Admin created to test a few stuffs ####


@app.route('/admin/course/create/', methods=['GET', 'POST'])
@login_required
def admin_course_create():
    """Provide HTML form to create a new resume record."""
    form = CourseForm(request.form)
    if request.method == 'POST' and form.validate():
        appt = Course(user_id=current_user.id)
        form.populate_obj(appt)
        db.session.add(appt)
        db.session.commit()
        # Success. Send the user back to the full resumes list.
        return redirect(url_for('course_list'))
    # Either first load or validation error at this point.
    return render_template('course/edit.html', form=form)


@app.route('/admin/resumes/create/', methods=['GET', 'POST'])
#@student_required
@login_required
def resumes_create():
    """Provide HTML form to create a new resume record."""
    form = ResumeForm(request.form)
    if request.method == 'POST' and form.validate():
        appt = Resume(user_id=current_user.id)
        form.populate_obj(appt)
        db.session.add(appt)
        db.session.commit()
        # Success. Send the user back to the full resumes list.
        return redirect(url_for('resumes_list'))
    # Either first load or validation error at this point.
    return render_template('resume/admin_edit.html', form=form)



####Admin coach activate try#####


@app.route('/admin/coach/activate/', methods=['GET', 'POST'])
#@student_required
#@login_required
def admin_coach_activate():
    """Provide HTML form to create a new resume record."""
    form = RegisterCoachForm(request.form)
    if request.method == 'POST' and form.validate():
        appt = CoachUserData(user_id=current_user.id)
        form.populate_obj(appt)
        db.session.add(appt)
        coach_role = user_datastore.find_role("ROLE_COACH")
        user_datastore.add_role_to_user(current_user, coach_role)
        db.session.commit()
        # Success. Send the user back to the full resumes list.
        return redirect(url_for('course_create'))
    # Either first load or validation error at this point.
    return render_template('course/edit_coach.html', form=form)

###############SEO URLS ############

@app.route('/learn-to-code-c++-Barcelona')
def tech_keyword_learn_1():
    return render_template('landing.html', title="learn how to code" , keyword="c++" , location="in Barcelona")
@app.route('/learn-to-code-c#-Barcelona')
def tech_keyword_learn_2():
    return render_template('landing.html', title="learn how to code" , keyword="c#" , location="in Barcelona")
@app.route('/learn-to-code-Ruby-Barcelona')
def tech_keyword_learn_3():
    return render_template('landing.html', title="learn how to code" , keyword="Ruby" , location="in Barcelona")
@app.route('/learn-to-code-Python-Barcelona')
def tech_keyword_learn_4():
    return render_template('landing.html', title="learn how to code" , keyword="Python" , location="in Barcelona")
@app.route('/learn-to-code-HTML5-Barcelona')
def tech_keyword_learn_5():
    return render_template('landing.html', title="learn how to code" , keyword="HTML5" , location="in Barcelona")
@app.route('/learn-to-code-Java-Barcelona')
def tech_keyword_learn_6():
    return render_template('landing.html', title="learn how to code" , keyword="Java" , location="in Barcelona")
@app.route('/learn-to-code-Perl-Barcelona')
def tech_keyword_learn_7():
    return render_template('landing.html', title="learn how to code" , keyword="Perl" , location="in Barcelona")
@app.route('/learn-to-code-Php-Barcelona')
def tech_keyword_learn_8():
    return render_template('landing.html', title="learn how to code" , keyword="Php" , location="in Barcelona")
    
@app.route('/learn-to-code-JavaScript-Barcelona')
def tech_keyword_learn_9():
    return render_template('landing.html', title="learn how to code" , keyword="JavaScript" , location="in Barcelona")
    
###########Guitar Keywords ########

@app.route('/learn-to-play-guitar-Barcelona')
def guitar_keyword_learn_1():
    return render_template('landing.html', title="learn to play" , keyword="guitar" , location="in Barcelona")
@app.route('/learn-how-to-play-guitar-Barcelona')
def guitar_keyword_learn_2():
    return render_template('landing.html', title="learn how to play" , keyword="guitar" , location="in Barcelona")
    
@app.route('/learn-to-play-the-guitar-Barcelona')
def guitar_keyword_learn_3():
    return render_template('landing.html', title="learn to play the" , keyword="guitar" , location="in Barcelona")
    
@app.route('/bass-guitar-lessons-for-beginners-barcelona')
def guitar_keyword_learn_4():
    return render_template('landing.html', title="beginner bass lessons " , keyword="guitar" , location="in Barcelona")
    
@app.route('/how-to-play-electric-bass-guitar-barcelona')
def guitar_keyword_learn_5():
    return render_template('landing.html', title="how to play" , keyword="electric bass guitar" , location="in Barcelona")

@app.route('/english-guitar-lessons-barcelona')
def guitar_keyword_learn_6():
    return render_template('landing.html', title="english" , keyword="guitar lessons" , location="in Barcelona")
###############Learn English #####
@app.route('/learn-english-for-business-communication-Barcelona')
def english_keyword_learn_1():
    return render_template('landing.html', title="learn " , keyword="english for business communication" , location="in Barcelona")
@app.route('/teach-english-in-Barcelona')
def english_keyword_learn_2():
    return render_template('landing.html', title="learn " , keyword="english" , location="in Barcelona")
@app.route('/english-teacher-in-Barcelona')
def english_keyword_learn_3():
    return render_template('landing.html', title="english " , keyword="teacher" , location="in Barcelona")
@app.route('/teach-english-in-barcelona-without-tefl')
def english_keyword_learn_4():
    return render_template('landing.html', title="english " , keyword="without tefl" , location="in Barcelona")
@app.route('/learn-new-languages-in-barcelona')
def languages_keyword_learn_2():
    return render_template('landing.html', title="learn " , keyword="new languages" , location="in Barcelona")
    
@app.route('/language-exchange-free-in-Barcelona')
def language_keyword_learn_3():
    return render_template('landing.html', title="language" , keyword="exchange" , location="in Barcelona")
    
@app.route('/global-tutor-Barcelona')
def tutor_keyword_barcelona_1():
    return render_template('landing.html', title="global " , keyword="tutor" , location="in Barcelona")
##### Salsa Classes Keywords ###

@app.route('/salsa-classes-in-barcelona')
def classes_keyword_salsa_1():
    return render_template('landing.html', title="salsa " , keyword="classes" , location="in Barcelona")

##### Yoga Classes Keywords ###
@app.route('/yoga-classes-in-barcelona')
def classes_keyword_yoga_1():
    return render_template('landing.html', title="yoga " , keyword="classes" , location="in Barcelona")

##### Programmming Level 2 Keywords ###
@app.route('/python-barcelona')
def programming_keyword_barcelona_1():
    return render_template('landing.html', title="python " , keyword="classes" , location="in Barcelona")
@app.route('/ruby-barcelona')
def programming_keyword_barcelona_2():
    return render_template('landing.html', title="ruby " , keyword="classes" , location="in Barcelona")
@app.route('/html5-barcelona')
def programming_keyword_barcelona_3():
    return render_template('landing.html', title="html5 " , keyword="classes" , location="in Barcelona")
@app.route('/java-barcelona')
def programming_keyword_barcelona_4():
    return render_template('landing.html', title="java " , keyword="classes" , location="in Barcelona")
@app.route('/django-barcelona')
def programming_keyword_barcelona_5():
    return render_template('landing.html', title="django " , keyword="classes" , location="in Barcelona")
@app.route('/javascript-barcelona')
def programming_keyword_barcelona_6():
    return render_template('landing.html', title="javascript " , keyword="classes" , location="in Barcelona")
@app.route('/learn-to-code-barcelona')
def programming_keyword_barcelona_7():
    return render_template('landing.html', title="learn to" , keyword="code" , location="Barcelona")
@app.route('/learn-to-code-c-sharp-barcelona')
def programming_keyword_barcelona_8():
    return render_template('landing.html', title="learn to code" , keyword="c sharp" , location="Barcelona")
@app.route('/learn-to-code-c++-barcelona')
def programming_keyword_barcelona_9():
    return render_template('landing.html', title="learn to code" , keyword="c++" , location="Barcelona")
@app.route('/learn-programming-in-barcelona')
def programming_keyword_barcelona_10():
    return render_template('landing.html', title="learn" , keyword="programming" , location="Barcelona")
@app.route('/learn-software-development-in-barcelona')
def programming_keyword_barcelona_11():
    return render_template('landing.html', title="learn" , keyword="software development" , location="Barcelona")
@app.route('/programming-classes-in-barcelona')
def programming_keyword_barcelona_12():
    return render_template('landing.html', title="programming" , keyword="classes" , location="Barcelona")
@app.route('/programming-courses-in-barcelona')
def programming_keyword_barcelona_13():
    return render_template('landing.html', title="programming" , keyword="courses" , location="Barcelona")
@app.route('/intensive-programming-classes-in-barcelona')
def programming_keyword_barcelona_14():
    return render_template('landing.html', title="intensive programming" , keyword="classes" , location="Barcelona")
@app.route('/cooking-course-barcelona')
def cooking_keyword_barcelona_1():
    return render_template('landing.html', title="cooking" , keyword="course" , location="Barcelona")
@app.route('/photography-course-barcelona')
def photography_keyword_barcelona_1():
    return render_template('landing.html', title="photography" , keyword="course" , location="Barcelona")
@app.route('/art-course-barcelona')
def art_keyword_barcelona_1():
    return render_template('landing.html', title="art" , keyword="course" , location="Barcelona")
@app.route('/group-exercise-classes-barcelona')
def exercise_keyword_barcelona_1():
    return render_template('landing.html', title="group" , keyword="exercise classes" , location="Barcelona")
@app.route('/i-want-to-learn-spanish')
def landing_students_1():
    return render_template('landing_students.html', title="i want to learn" , keyword="spanish" , location="Barcelona")
@app.route('/where-to-learn-computer-programming')
def landing_students_2():
    return render_template('landing_students.html', title="where can I learn" , keyword="computer programming" , location="Barcelona")
@app.route('/easy-way-to-learn-computer-programming')
def landing_students_3():
    return render_template('landing_students.html', title="easy way to learn" , keyword="computer programming" , location="Barcelona")
@app.route('/best-way-to-learn-python-2016')
def landing_students_4():
    return render_template('landing_students.html', title="best way to learn" , keyword="python 2016" , location="Barcelona")
@app.route('/private-courses-after-graduation')
def landing_students_5():
    return render_template('landing_students.html', title="private" , keyword="courses after graduation" , location="Barcelona")
@app.route('/private-courses-after-graduation')
def landing_students_6():
    return render_template('landing_students.html', title="private" , keyword="courses after graduation" , location="Barcelona")
@app.route('/professional-courses-in-commerce-after-graduation')
def landing_students_7():
    return render_template('landing_students.html', title="professional" , keyword="courses in commerce after graduation" , location="Barcelona")
@app.route('/diploma-courses-after-graduation-in-commerce')
def landing_students_8():
    return render_template('landing_students.html', title="diploma" , keyword="courses after graduation in commerce" , location="Barcelona")
@app.route('/new-courses-for-commerce-students-after-graduation')
def landing_students_9():
    return render_template('landing_students.html', title="new" , keyword="courses for commerce students after graduation" , location="Barcelona")
@app.route('/teach-english-abroad-without-tefl-or-degree')
def landing_students_10():
    return render_template('landing_students.html', title="teach abroad without tefl or degree in" , keyword="english" , location="Barcelona")

#####################USA CITIES KEYWORDS START###########
@app.route('/free-computer-classes-nyc')
def landing_usa_free1():
    return render_template('landing_usa.html', data="free computer classes nyc ")
@app.route('/free-computer-classes-near-me')
def landing_usa_free2():
    return render_template('landing_usa.html', data="free-computer classes near me ")
@app.route('/free-computer-classes-in-chicago')
def landing_usa_free3():
    return render_template('landing_usa.html', data="free computer classes in chicago ")
@app.route('/free-computer-classes-in-philadelphia')
def landing_usa_free4():
    return render_template('landing_usa.html', data="free computer classes in philadelphia ")
@app.route('/free-computer-classes-in-houston')
def landing_usa_free5():
    return render_template('landing_usa.html', data="free computer classes in houston")
@app.route('/free-computer-classes-in-dc')
def landing_usa_free6():
    return render_template('landing_usa.html', data="free computer classes in dc")
@app.route('/free-computer-classes-for-adults-in-nyc')
def landing_usa_free7():
    return render_template('landing_usa.html', data="free computer classes for adults in nyc")
@app.route('/free-computer-classes-san-diego')
def landing_usa_free8():
    return render_template('landing_usa.html', data="free computer classes san diego")
@app.route('/free-computer-classes-nj')
def landing_usa_free9():
    return render_template('landing_usa.html', data="free computer classes nj")

@app.route('/free-computer-classes-in-las-vegas')
def landing_usa_free10():
    return render_template('landing_usa.html', data="free computer classes in las vegas")
@app.route('/free-computer-classes-in-nyc')
def landing_usa_free11():
    return render_template('landing_usa.html', data="free computer classes in nyc")
@app.route('/free-computer-classes-buffalo-ny')
def landing_usa_free12():
    return render_template('landing_usa.html', data="free computer classes buffalo ny")
@app.route('/free-computer-classes-los-angeles')
def landing_usa_free13():
    return render_template('landing_usa.html', data="free computer classes los angeles")
@app.route('/free-computer-classes-in-columbus-ohio')
def landing_usa_free14():
    return render_template('landing_usa.html', data="free computer classes in columbus ohio")
@app.route('/free-computer-classes-charlotte-nc')
def landing_usa_free15():
    return render_template('landing_usa.html', data="free computer classes charlotte nc")
@app.route('/free-computer-classes-philadelphia')
def landing_usa_free16():
    return render_template('landing_usa.html', data="free computer classes philadelphia")
@app.route('/free-computer-classes-seattle')
def landing_usa_free17():
    return render_template('landing_usa.html', data="free computer classes seattle")
@app.route('/free-computer-classes-minneapolis')
def landing_usa_free18():
    return render_template('landing_usa.html', data="free computer classes minneapolis")
@app.route('/free-computer-classes-austin')
def landing_usa_free19():
    return render_template('landing_usa.html', data="free computer classes austin")

@app.route('/free-computer-classes-in-dallas-tx')
def landing_usa_free20():
    return render_template('landing_usa.html', data="free computer classes in dallas tx")
@app.route('/free-computer-classes-in-ri')
def landing_usa_free21():
    return render_template('landing_usa.html', data="free computer classes in ri")
@app.route('/free-computer-classes-in-san-antonio-tx')
def landing_usa_free22():
    return render_template('landing_usa.html', data="free computer classes in san antonio tx")
@app.route('/free-computer-classes-new-orleans')
def landing_usa_free23():
    return render_template('landing_usa.html', data="free computer classes new orleans")
@app.route('/free-computer-classes-nashville-tn')
def landing_usa_free24():
    return render_template('landing_usa.html', data="free computer classes nashville tn")
@app.route('/free-computer-classes-boston')
def landing_usa_free25():
    return render_template('landing_usa.html', data="free computer classes boston")
@app.route('/free-computer-classes-denver')
def landing_usa_free26():
    return render_template('landing_usa.html', data="free computer classes denver")
@app.route('/free-computer-classes-brooklyn')
def landing_usa_free27():
    return render_template('landing_usa.html', data="free computer classes brooklyn")
@app.route('/free-computer-classes-miami')
def landing_usa_free28():
    return render_template('landing_usa.html', data="free computer classes miami")
@app.route('/free-computer-classes-houston')
def landing_usa_free29():
    return render_template('landing_usa.html', data="free computer classes houston")

@app.route('/free-computer-classes-bronx')
def landing_usa_free30():
    return render_template('landing_usa.html', data="free computer classes bronx")
@app.route('/free-computer-classes-birmingham-al')
def landing_usa_free31():
    return render_template('landing_usa.html', data="free computer classes birmingham al")
@app.route('/free-computer-classes-san-francisco')
def landing_usa_free32():
    return render_template('landing_usa.html', data="free computer classes san francisco")
@app.route('/free-computer-classes-in-atlanta-ga')
def landing_usa_free33():
    return render_template('landing_usa.html', data="free computer classes in atlanta ga")
@app.route('/free-computer-classes-phoenix-az')
def landing_usa_free34():
    return render_template('landing_usa.html', data="free computer classes phoenix az")
@app.route('/free-computer-classes-richmond-va')
def landing_usa_free35():
    return render_template('landing_usa.html', data="free computer classes richmond va")
@app.route('/free-computer-classes-mn')
def landing_usa_free36():
    return render_template('landing_usa.html', data="free computer classes mn")
@app.route('/free-computer-classes-san-antonio-tx')
def landing_usa_free37():
    return render_template('landing_usa.html', data="free computer classes san antonio tx")
@app.route('/free-computer-classes-sacramento')
def landing_usa_free38():
    return render_template('landing_usa.html', data="free computer classes sacramento")
@app.route('/free-computer-classes-austin-tx')
def landing_usa_free39():
    return render_template('landing_usa.html', data="free computer classes austin tx")

@app.route('/free-computer-classes-rochester-ny')
def landing_usa_free40():
    return render_template('landing_usa.html', data="free computer classes rochester ny")
@app.route('/free-computer-classes-in-charlotte-nc')
def landing_usa_free41():
    return render_template('landing_usa.html', data="free computer classes in charlotte nc")
@app.route('/free-computer-classes-tucson')
def landing_usa_free42():
    return render_template('landing_usa.html', data="free computer classes tucson")
@app.route('/free-computer-classes-pittsburgh')
def landing_usa_free43():
    return render_template('landing_usa.html', data="free computer classes pittsburgh")
@app.route('/free-computer-classes-in-detroit')
def landing_usa_free44():
    return render_template('landing_usa.html', data="free computer classes in detroit")
@app.route('/free-computer-classes-kansas-city')
def landing_usa_free45():
    return render_template('landing_usa.html', data="free computer classes kansas city")
@app.route('/free-computer-classes-detroit')
def landing_usa_free46():
    return render_template('landing_usa.html', data="free computer classes detroit")
@app.route('/free-computer-classes-on-the-internet')
def landing_usa_free47():
    return render_template('landing_usa.html', data=" ")
@app.route('/teach-english-abroad-without-tefl-or-degree')
def landing_usa_free48():
    return render_template('landing_usa.html', data="free computer classes on the internet")
@app.route('/free-computer-classes-mesa-az')
def landing_usa_free49():
    return render_template('landing_usa.html', data="free computer classes mesa az")

@app.route('/free-computer-classes-greenville-sc')
def landing_usa_free50():
    return render_template('landing_usa.html', data="free computer classes greenville sc")
@app.route('/free-computer-classes-washington-dc')
def landing_usa_free51():
    return render_template('landing_usa.html', data="free computer classes washington dc")
@app.route('/free-computer-classes-louisville-ky')
def landing_usa_free52():
    return render_template('landing_usa.html', data="free computer classes louisville ky")
@app.route('/free-computer-classes-in-knoxville-tn')
def landing_usa_free53():
    return render_template('landing_usa.html', data="free computer classes in knoxville tn")
@app.route('/free-computer-classes-colorado-springs')
def landing_usa_free54():
    return render_template('landing_usa.html', data="free computer classes colorado springs")
@app.route('/free-computer-classes-memphis-tn')
def landing_usa_free55():
    return render_template('landing_usa.html', data="free computer classes memphis tn")
@app.route('/free-computer-classes-phoenix')
def landing_usa_free56():
    return render_template('landing_usa.html', data="free computer classes phoenix")
@app.route('/free-computer-classes-boston-ma')
def landing_usa_free57():
    return render_template('landing_usa.html', data="free computer classes boston ma")
@app.route('/free-computer-classes-st-louis-mo')
def landing_usa_free58():
    return render_template('landing_usa.html', data="free computer classes st louis mo")
@app.route('/free-computer-classes-atlanta-ga')
def landing_usa_free59():
    return render_template('landing_usa.html', data="free computer classes atlanta ga")

@app.route('/free-computer-classes-baton-rouge')
def landing_usa_free60():
    return render_template('landing_usa.html', data="free computer classes baton rouge")
@app.route('/free-computer-classes-in-houston-texas')
def landing_usa_free61():
    return render_template('landing_usa.html', data="free computer classes in houston texas")
@app.route('/free-computer-classes-san-antonio')
def landing_usa_free62():
    return render_template('landing_usa.html', data="free computer classes san antonio")
@app.route('/free-computer-classes-houston-tx')
def landing_usa_free63():
    return render_template('landing_usa.html', data="free computer classes houston tx")
@app.route('/free-computer-classes-dallas-tx')
def landing_usa_free64():
    return render_template('landing_usa.html', data=" ")
@app.route('/free-computer-classes-portland-oregon')
def landing_usa_free65():
    return render_template('landing_usa.html', data="free computer classes portland oregon")
@app.route('/free-computer-classes-queens-ny')
def landing_usa_free66():
    return render_template('landing_usa.html', data="free computer classes queens ny")
@app.route('/free-computer-classes-cleveland-ohio')
def landing_usa_free67():
    return render_template('landing_usa.html', data="free computer classes cleveland ohio")
@app.route('/free-computer-classes-bronx-ny')
def landing_usa_free68():
    return render_template('landing_usa.html', data="free computer classes bronx ny")
@app.route('/free-computer-classes-tampa')
def landing_usa_free69():
    return render_template('landing_usa.html', data="free computer classes tampa")

@app.route('/free-computer-classes-albany-ny')
def landing_usa_free70():
    return render_template('landing_usa.html', data="free computer classes albany ny")
@app.route('/free-computer-classes-tampa-fl')
def landing_usa_free71():
    return render_template('landing_usa.html', data="free computer classes tampa fl")
@app.route('/free-computer-classes-brooklyn-ny')
def landing_usa_free72():
    return render_template('landing_usa.html', data="free computer classes brooklyn ny")
@app.route('/free-computer-classes-dc')
def landing_usa_free73():
    return render_template('landing_usa.html', data="free computer classes dc")
@app.route('/free-computer-classes-knoxville-tne')
def landing_usa_free74():
    return render_template('landing_usa.html', data="free computer classes knoxville tn")
@app.route('/free-computer-classes-raleigh-nc')
def landing_usa_free75():
    return render_template('landing_usa.html', data="free computer classes raleigh nc")
@app.route('/free-computer-classes-staten-island-ny')
def landing_usa_free76():
    return render_template('landing_usa.html', data="free computer classes staten island ny")
@app.route('/free-computer-classes-anchorage-ak')
def landing_usa_free77():
    return render_template('landing_usa.html', data="free computer classes anchorage ak")
@app.route('/free-computer-classes-courses')
def landing_usa_free78():
    return render_template('landing_usa.html', data="free computer classes courses")
@app.route('/free-computer-classes-sacramento-ca')
def landing_usa_free79():
    return render_template('landing_usa.html', data="free computer classes sacramento ca")

@app.route('/free-computer-classes-chicago-il')
def landing_usa_free80():
    return render_template('landing_usa.html', data="free computer classes chicago il")
@app.route('/free-computer-classes-miami-fl')
def landing_usa_free81():
    return render_template('landing_usa.html', data="free computer classes miami fl")
@app.route('/free-computer-classes-bakersfield-ca')
def landing_usa_free82():
    return render_template('landing_usa.html', data="free computer classes bakersfield ca")
@app.route('/free-computer-classes-baltimore-md')
def landing_usa_free83():
    return render_template('landing_usa.html', data="free computer classes baltimore md")
@app.route('/free-computer-classes-new-york')
def landing_usa_free84():
    return render_template('landing_usa.html', data="free computer classes new york")
@app.route('/free-computer-classes-las-vegas-nv')
def landing_usa_free85():
    return render_template('landing_usa.html', data="free computer classes las vegas nv")
@app.route('/free-computer-classes-san-diego-ca')
def landing_usa_free86():
    return render_template('landing_usa.html', data="free computer classes san diego ca")
@app.route('/free-computer-classes-austin-texas')
def landing_usa_free87():
    return render_template('landing_usa.html', data="free computer classes austin texas")
@app.route('/free-computer-classes-milwaukee')
def landing_usa_free88():
    return render_template('landing_usa.html', data="free computer classes milwaukee")
@app.route('/free-computer-classes-reno-nv')
def landing_usa_free89():
    return render_template('landing_usa.html', data="free computer classes reno nv")

@app.route('/free-computer-classes-oklahoma-city')
def landing_usa_free90():
    return render_template('landing_usa.html', data="free computer classes oklahoma city")
@app.route('/free-computer-classes-erie-pa')
def landing_usa_free91():
    return render_template('landing_usa.html', data="free computer classes erie pa")
@app.route('/free-computer-classes-for-adults-in-chicago')
def landing_usa_free92():
    return render_template('landing_usa.html', data="free computer classes for adults in chicago")
###############################################################################Computer Programming Classes #############
@app.route('/computer-programming-classes-nyc')
def landing_usa_computer_programming1():
    return render_template('landing_usa.html', data="computer programming classes nyc ")
@app.route('/computer-programming-classes-near-me')
def landing_usa_computer_programming2():
    return render_template('landing_usa.html', data="computer-programming classes near me ")
@app.route('/computer-programming-classes-in-chicago')
def landing_usa_computer_programming3():
    return render_template('landing_usa.html', data="computer programming classes in chicago ")
@app.route('/computer-programming-classes-in-philadelphia')
def landing_usa_computer_programming4():
    return render_template('landing_usa.html', data="computer programming classes in philadelphia ")
@app.route('/computer-programming-classes-in-houston')
def landing_usa_computer_programming5():
    return render_template('landing_usa.html', data="computer programming classes in houston")
@app.route('/computer-programming-classes-in-dc')
def landing_usa_computer_programming6():
    return render_template('landing_usa.html', data="computer programming classes in dc")
@app.route('/computer-programming-classes-for-adults-in-nyc')
def landing_usa_computer_programming7():
    return render_template('landing_usa.html', data="computer programming classes for adults in nyc")
@app.route('/computer-programming-classes-san-diego')
def landing_usa_computer_programming8():
    return render_template('landing_usa.html', data="computer programming classes san diego")
@app.route('/computer-programming-classes-nj')
def landing_usa_computer_programming9():
    return render_template('landing_usa.html', data="computer programming classes nj")

@app.route('/computer-programming-classes-in-las-vegas')
def landing_usa_computer_programming10():
    return render_template('landing_usa.html', data="computer programming classes in las vegas")
@app.route('/computer-programming-classes-in-nyc')
def landing_usa_computer_programming11():
    return render_template('landing_usa.html', data="computer programming classes in nyc")
@app.route('/computer-programming-classes-buffalo-ny')
def landing_usa_computer_programming12():
    return render_template('landing_usa.html', data="computer programming classes buffalo ny")
@app.route('/computer-programming-classes-los-angeles')
def landing_usa_computer_programming13():
    return render_template('landing_usa.html', data="computer programming classes los angeles")
@app.route('/computer-programming-classes-in-columbus-ohio')
def landing_usa_computer_programming14():
    return render_template('landing_usa.html', data="computer programming classes in columbus ohio")
@app.route('/computer-programming-classes-charlotte-nc')
def landing_usa_computer_programming15():
    return render_template('landing_usa.html', data="computer programming classes charlotte nc")
@app.route('/computer-programming-classes-philadelphia')
def landing_usa_computer_programming16():
    return render_template('landing_usa.html', data="computer programming classes philadelphia")
@app.route('/computer-programming-classes-seattle')
def landing_usa_computer_programming17():
    return render_template('landing_usa.html', data="computer programming classes seattle")
@app.route('/computer-programming-classes-minneapolis')
def landing_usa_computer_programming18():
    return render_template('landing_usa.html', data="computer programming classes minneapolis")
@app.route('/computer-programming-classes-austin')
def landing_usa_computer_programming19():
    return render_template('landing_usa.html', data="computer programming classes austin")

@app.route('/computer-programming-classes-in-dallas-tx')
def landing_usa_computer_programming20():
    return render_template('landing_usa.html', data="computer programming classes in dallas tx")
@app.route('/computer-programming-classes-in-ri')
def landing_usa_computer_programming21():
    return render_template('landing_usa.html', data="computer programming classes in ri")
@app.route('/computer-programming-classes-in-san-antonio-tx')
def landing_usa_computer_programming22():
    return render_template('landing_usa.html', data="computer programming classes in san antonio tx")
@app.route('/computer-programming-classes-new-orleans')
def landing_usa_computer_programming23():
    return render_template('landing_usa.html', data="computer programming classes new orleans")
@app.route('/computer-programming-classes-nashville-tn')
def landing_usa_computer_programming24():
    return render_template('landing_usa.html', data="computer programming classes nashville tn")
@app.route('/computer-programming-classes-boston')
def landing_usa_computer_programming25():
    return render_template('landing_usa.html', data="computer programming classes boston")
@app.route('/computer-programming-classes-denver')
def landing_usa_computer_programming26():
    return render_template('landing_usa.html', data="computer programming classes denver")
@app.route('/computer-programming-classes-brooklyn')
def landing_usa_computer_programming27():
    return render_template('landing_usa.html', data="computer programming classes brooklyn")
@app.route('/computer-programming-classes-miami')
def landing_usa_computer_programming28():
    return render_template('landing_usa.html', data="computer programming classes miami")
@app.route('/computer-programming-classes-houston')
def landing_usa_computer_programming29():
    return render_template('landing_usa.html', data="computer programming classes houston")

@app.route('/computer-programming-classes-bronx')
def landing_usa_computer_programming30():
    return render_template('landing_usa.html', data="computer programming classes bronx")
@app.route('/computer-programming-classes-birmingham-al')
def landing_usa_computer_programming31():
    return render_template('landing_usa.html', data="computer programming classes birmingham al")
@app.route('/computer-programming-classes-san-francisco')
def landing_usa_computer_programming32():
    return render_template('landing_usa.html', data="computer programming classes san francisco")
@app.route('/computer-programming-classes-in-atlanta-ga')
def landing_usa_computer_programming33():
    return render_template('landing_usa.html', data="computer programming classes in atlanta ga")
@app.route('/computer-programming-classes-phoenix-az')
def landing_usa_computer_programming34():
    return render_template('landing_usa.html', data="computer programming classes phoenix az")
@app.route('/computer-programming-classes-richmond-va')
def landing_usa_computer_programming35():
    return render_template('landing_usa.html', data="computer programming classes richmond va")
@app.route('/computer-programming-classes-mn')
def landing_usa_computer_programming36():
    return render_template('landing_usa.html', data="computer programming classes mn")
@app.route('/computer-programming-classes-san-antonio-tx')
def landing_usa_computer_programming37():
    return render_template('landing_usa.html', data="computer programming classes san antonio tx")
@app.route('/computer-programming-classes-sacramento')
def landing_usa_computer_programming38():
    return render_template('landing_usa.html', data="computer programming classes sacramento")
@app.route('/computer-programming-classes-austin-tx')
def landing_usa_computer_programming39():
    return render_template('landing_usa.html', data="computer programming classes austin tx")

@app.route('/computer-programming-classes-rochester-ny')
def landing_usa_computer_programming40():
    return render_template('landing_usa.html', data="computer programming classes rochester ny")
@app.route('/computer-programming-classes-in-charlotte-nc')
def landing_usa_computer_programming41():
    return render_template('landing_usa.html', data="computer programming classes in charlotte nc")
@app.route('/computer-programming-classes-tucson')
def landing_usa_computer_programming42():
    return render_template('landing_usa.html', data="computer programming classes tucson")
@app.route('/computer-programming-classes-pittsburgh')
def landing_usa_computer_programming43():
    return render_template('landing_usa.html', data="computer programming classes pittsburgh")
@app.route('/computer-programming-classes-in-detroit')
def landing_usa_computer_programming44():
    return render_template('landing_usa.html', data="computer programming classes in detroit")
@app.route('/computer-programming-classes-kansas-city')
def landing_usa_computer_programming45():
    return render_template('landing_usa.html', data="computer programming classes kansas city")
@app.route('/computer-programming-classes-detroit')
def landing_usa_computer_programming46():
    return render_template('landing_usa.html', data="computer programming classes detroit")
@app.route('/computer-programming-classes-on-the-internet')
def landing_usa_computer_programming47():
    return render_template('landing_usa.html', data=" ")
@app.route('/teach-english-abroad-without-tefl-or-degree')
def landing_usa_computer_programming48():
    return render_template('landing_usa.html', data="computer programming classes on the internet")
@app.route('/computer-programming-classes-mesa-az')
def landing_usa_computer_programming49():
    return render_template('landing_usa.html', data="computer programming classes mesa az")

@app.route('/computer-programming-classes-greenville-sc')
def landing_usa_computer_programming50():
    return render_template('landing_usa.html', data="computer programming classes greenville sc")
@app.route('/computer-programming-classes-washington-dc')
def landing_usa_computer_programming51():
    return render_template('landing_usa.html', data="computer programming classes washington dc")
@app.route('/computer-programming-classes-louisville-ky')
def landing_usa_computer_programming52():
    return render_template('landing_usa.html', data="computer programming classes louisville ky")
@app.route('/computer-programming-classes-in-knoxville-tn')
def landing_usa_computer_programming53():
    return render_template('landing_usa.html', data="computer programming classes in knoxville tn")
@app.route('/computer-programming-classes-colorado-springs')
def landing_usa_computer_programming54():
    return render_template('landing_usa.html', data="computer programming classes colorado springs")
@app.route('/computer-programming-classes-memphis-tn')
def landing_usa_computer_programming55():
    return render_template('landing_usa.html', data="computer programming classes memphis tn")
@app.route('/computer-programming-classes-phoenix')
def landing_usa_computer_programming56():
    return render_template('landing_usa.html', data="computer programming classes phoenix")
@app.route('/computer-programming-classes-boston-ma')
def landing_usa_computer_programming57():
    return render_template('landing_usa.html', data="computer programming classes boston ma")
@app.route('/computer-programming-classes-st-louis-mo')
def landing_usa_computer_programming58():
    return render_template('landing_usa.html', data="computer programming classes st louis mo")
@app.route('/computer-programming-classes-atlanta-ga')
def landing_usa_computer_programming59():
    return render_template('landing_usa.html', data="computer programming classes atlanta ga")

@app.route('/computer-programming-classes-baton-rouge')
def landing_usa_computer_programming60():
    return render_template('landing_usa.html', data="computer programming classes baton rouge")
@app.route('/computer-programming-classes-in-houston-texas')
def landing_usa_computer_programming61():
    return render_template('landing_usa.html', data="computer programming classes in houston texas")
@app.route('/computer-programming-classes-san-antonio')
def landing_usa_computer_programming62():
    return render_template('landing_usa.html', data="computer programming classes san antonio")
@app.route('/computer-programming-classes-houston-tx')
def landing_usa_computer_programming63():
    return render_template('landing_usa.html', data="computer programming classes houston tx")
@app.route('/computer-programming-classes-dallas-tx')
def landing_usa_computer_programming64():
    return render_template('landing_usa.html', data=" ")
@app.route('/computer-programming-classes-portland-oregon')
def landing_usa_computer_programming65():
    return render_template('landing_usa.html', data="computer programming classes portland oregon")
@app.route('/computer-programming-classes-queens-ny')
def landing_usa_computer_programming66():
    return render_template('landing_usa.html', data="computer programming classes queens ny")
@app.route('/computer-programming-classes-cleveland-ohio')
def landing_usa_computer_programming67():
    return render_template('landing_usa.html', data="computer programming classes cleveland ohio")
@app.route('/computer-programming-classes-bronx-ny')
def landing_usa_computer_programming68():
    return render_template('landing_usa.html', data="computer programming classes bronx ny")
@app.route('/computer-programming-classes-tampa')
def landing_usa_computer_programming69():
    return render_template('landing_usa.html', data="computer programming classes tampa")

@app.route('/computer-programming-classes-albany-ny')
def landing_usa_computer_programming70():
    return render_template('landing_usa.html', data="computer programming classes albany ny")
@app.route('/computer-programming-classes-tampa-fl')
def landing_usa_computer_programming71():
    return render_template('landing_usa.html', data="computer programming classes tampa fl")
@app.route('/computer-programming-classes-brooklyn-ny')
def landing_usa_computer_programming72():
    return render_template('landing_usa.html', data="computer programming classes brooklyn ny")
@app.route('/computer-programming-classes-dc')
def landing_usa_computer_programming73():
    return render_template('landing_usa.html', data="computer programming classes dc")
@app.route('/computer-programming-classes-knoxville-tne')
def landing_usa_computer_programming74():
    return render_template('landing_usa.html', data="computer programming classes knoxville tn")
@app.route('/computer-programming-classes-raleigh-nc')
def landing_usa_computer_programming75():
    return render_template('landing_usa.html', data="computer programming classes raleigh nc")
@app.route('/computer-programming-classes-staten-island-ny')
def landing_usa_computer_programming76():
    return render_template('landing_usa.html', data="computer programming classes staten island ny")
@app.route('/computer-programming-classes-anchorage-ak')
def landing_usa_computer_programming77():
    return render_template('landing_usa.html', data="computer programming classes anchorage ak")
@app.route('/computer-programming-classes-courses')
def landing_usa_computer_programming78():
    return render_template('landing_usa.html', data="computer programming classes courses")
@app.route('/computer-programming-classes-sacramento-ca')
def landing_usa_computer_programming79():
    return render_template('landing_usa.html', data="computer programming classes sacramento ca")

@app.route('/computer-programming-classes-chicago-il')
def landing_usa_computer_programming80():
    return render_template('landing_usa.html', data="computer programming classes chicago il")
@app.route('/computer-programming-classes-miami-fl')
def landing_usa_computer_programming81():
    return render_template('landing_usa.html', data="computer programming classes miami fl")
@app.route('/computer-programming-classes-bakersfield-ca')
def landing_usa_computer_programming82():
    return render_template('landing_usa.html', data="computer programming classes bakersfield ca")
@app.route('/computer-programming-classes-baltimore-md')
def landing_usa_computer_programming83():
    return render_template('landing_usa.html', data="computer programming classes baltimore md")
@app.route('/computer-programming-classes-new-york')
def landing_usa_computer_programming84():
    return render_template('landing_usa.html', data="computer programming classes new york")
@app.route('/computer-programming-classes-las-vegas-nv')
def landing_usa_computer_programming85():
    return render_template('landing_usa.html', data="computer programming classes las vegas nv")
@app.route('/computer-programming-classes-san-diego-ca')
def landing_usa_computer_programming86():
    return render_template('landing_usa.html', data="computer programming classes san diego ca")
@app.route('/computer-programming-classes-austin-texas')
def landing_usa_computer_programming87():
    return render_template('landing_usa.html', data="computer programming classes austin texas")
@app.route('/computer-programming-classes-milwaukee')
def landing_usa_computer_programming88():
    return render_template('landing_usa.html', data="computer programming classes milwaukee")
@app.route('/computer-programming-classes-reno-nv')
def landing_usa_computer_programming89():
    return render_template('landing_usa.html', data="computer programming classes reno nv")

@app.route('/computer-programming-classes-oklahoma-city')
def landing_usa_computer_programming90():
    return render_template('landing_usa.html', data="computer programming classes oklahoma city")
@app.route('/computer-programming-classes-erie-pa')
def landing_usa_computer_programming91():
    return render_template('landing_usa.html', data="computer programming classes erie pa")
@app.route('/computer-programming-classes-for-adults-in-chicago')
def landing_usa_computer_programming92():
    return render_template('landing_usa.html', data="computer programming classes for adults in chicago")
####################################################################Computer Science Classes###############
@app.route('/computer-science-classes-nyc')
def landing_usa_computer_science1():
    return render_template('landing_usa.html', data="computer science classes nyc ")
@app.route('/computer-science-classes-near-me')
def landing_usa_computer_science2():
    return render_template('landing_usa.html', data="computer-science classes near me ")
@app.route('/computer-science-classes-in-chicago')
def landing_usa_computer_science3():
    return render_template('landing_usa.html', data="computer science classes in chicago ")
@app.route('/computer-science-classes-in-philadelphia')
def landing_usa_computer_science4():
    return render_template('landing_usa.html', data="computer science classes in philadelphia ")
@app.route('/computer-science-classes-in-houston')
def landing_usa_computer_science5():
    return render_template('landing_usa.html', data="computer science classes in houston")
@app.route('/computer-science-classes-in-dc')
def landing_usa_computer_science6():
    return render_template('landing_usa.html', data="computer science classes in dc")
@app.route('/computer-science-classes-for-adults-in-nyc')
def landing_usa_computer_science7():
    return render_template('landing_usa.html', data="computer science classes for adults in nyc")
@app.route('/computer-science-classes-san-diego')
def landing_usa_computer_science8():
    return render_template('landing_usa.html', data="computer science classes san diego")
@app.route('/computer-science-classes-nj')
def landing_usa_computer_science9():
    return render_template('landing_usa.html', data="computer science classes nj")

@app.route('/computer-science-classes-in-las-vegas')
def landing_usa_computer_science10():
    return render_template('landing_usa.html', data="computer science classes in las vegas")
@app.route('/computer-science-classes-in-nyc')
def landing_usa_computer_science11():
    return render_template('landing_usa.html', data="computer science classes in nyc")
@app.route('/computer-science-classes-buffalo-ny')
def landing_usa_computer_science12():
    return render_template('landing_usa.html', data="computer science classes buffalo ny")
@app.route('/computer-science-classes-los-angeles')
def landing_usa_computer_science13():
    return render_template('landing_usa.html', data="computer science classes los angeles")
@app.route('/computer-science-classes-in-columbus-ohio')
def landing_usa_computer_science14():
    return render_template('landing_usa.html', data="computer science classes in columbus ohio")
@app.route('/computer-science-classes-charlotte-nc')
def landing_usa_computer_science15():
    return render_template('landing_usa.html', data="computer science classes charlotte nc")
@app.route('/computer-science-classes-philadelphia')
def landing_usa_computer_science16():
    return render_template('landing_usa.html', data="computer science classes philadelphia")
@app.route('/computer-science-classes-seattle')
def landing_usa_computer_science17():
    return render_template('landing_usa.html', data="computer science classes seattle")
@app.route('/computer-science-classes-minneapolis')
def landing_usa_computer_science18():
    return render_template('landing_usa.html', data="computer science classes minneapolis")
@app.route('/computer-science-classes-austin')
def landing_usa_computer_science19():
    return render_template('landing_usa.html', data="computer science classes austin")

@app.route('/computer-science-classes-in-dallas-tx')
def landing_usa_computer_science20():
    return render_template('landing_usa.html', data="computer science classes in dallas tx")
@app.route('/computer-science-classes-in-ri')
def landing_usa_computer_science21():
    return render_template('landing_usa.html', data="computer science classes in ri")
@app.route('/computer-science-classes-in-san-antonio-tx')
def landing_usa_computer_science22():
    return render_template('landing_usa.html', data="computer science classes in san antonio tx")
@app.route('/computer-science-classes-new-orleans')
def landing_usa_computer_science23():
    return render_template('landing_usa.html', data="computer science classes new orleans")
@app.route('/computer-science-classes-nashville-tn')
def landing_usa_computer_science24():
    return render_template('landing_usa.html', data="computer science classes nashville tn")
@app.route('/computer-science-classes-boston')
def landing_usa_computer_science25():
    return render_template('landing_usa.html', data="computer science classes boston")
@app.route('/computer-science-classes-denver')
def landing_usa_computer_science26():
    return render_template('landing_usa.html', data="computer science classes denver")
@app.route('/computer-science-classes-brooklyn')
def landing_usa_computer_science27():
    return render_template('landing_usa.html', data="computer science classes brooklyn")
@app.route('/computer-science-classes-miami')
def landing_usa_computer_science28():
    return render_template('landing_usa.html', data="computer science classes miami")
@app.route('/computer-science-classes-houston')
def landing_usa_computer_science29():
    return render_template('landing_usa.html', data="computer science classes houston")

@app.route('/computer-science-classes-bronx')
def landing_usa_computer_science30():
    return render_template('landing_usa.html', data="computer science classes bronx")
@app.route('/computer-science-classes-birmingham-al')
def landing_usa_computer_science31():
    return render_template('landing_usa.html', data="computer science classes birmingham al")
@app.route('/computer-science-classes-san-francisco')
def landing_usa_computer_science32():
    return render_template('landing_usa.html', data="computer science classes san francisco")
@app.route('/computer-science-classes-in-atlanta-ga')
def landing_usa_computer_science33():
    return render_template('landing_usa.html', data="computer science classes in atlanta ga")
@app.route('/computer-science-classes-phoenix-az')
def landing_usa_computer_science34():
    return render_template('landing_usa.html', data="computer science classes phoenix az")
@app.route('/computer-science-classes-richmond-va')
def landing_usa_computer_science35():
    return render_template('landing_usa.html', data="computer science classes richmond va")
@app.route('/computer-science-classes-mn')
def landing_usa_computer_science36():
    return render_template('landing_usa.html', data="computer science classes mn")
@app.route('/computer-science-classes-san-antonio-tx')
def landing_usa_computer_science37():
    return render_template('landing_usa.html', data="computer science classes san antonio tx")
@app.route('/computer-science-classes-sacramento')
def landing_usa_computer_science38():
    return render_template('landing_usa.html', data="computer science classes sacramento")
@app.route('/computer-science-classes-austin-tx')
def landing_usa_computer_science39():
    return render_template('landing_usa.html', data="computer science classes austin tx")

@app.route('/computer-science-classes-rochester-ny')
def landing_usa_computer_science40():
    return render_template('landing_usa.html', data="computer science classes rochester ny")
@app.route('/computer-science-classes-in-charlotte-nc')
def landing_usa_computer_science41():
    return render_template('landing_usa.html', data="computer science classes in charlotte nc")
@app.route('/computer-science-classes-tucson')
def landing_usa_computer_science42():
    return render_template('landing_usa.html', data="computer science classes tucson")
@app.route('/computer-science-classes-pittsburgh')
def landing_usa_computer_science43():
    return render_template('landing_usa.html', data="computer science classes pittsburgh")
@app.route('/computer-science-classes-in-detroit')
def landing_usa_computer_science44():
    return render_template('landing_usa.html', data="computer science classes in detroit")
@app.route('/computer-science-classes-kansas-city')
def landing_usa_computer_science45():
    return render_template('landing_usa.html', data="computer science classes kansas city")
@app.route('/computer-science-classes-detroit')
def landing_usa_computer_science46():
    return render_template('landing_usa.html', data="computer science classes detroit")
@app.route('/computer-science-classes-on-the-internet')
def landing_usa_computer_science47():
    return render_template('landing_usa.html', data=" ")
@app.route('/teach-english-abroad-without-tefl-or-degree')
def landing_usa_computer_science48():
    return render_template('landing_usa.html', data="computer science classes on the internet")
@app.route('/computer-science-classes-mesa-az')
def landing_usa_computer_science49():
    return render_template('landing_usa.html', data="computer science classes mesa az")

@app.route('/computer-science-classes-greenville-sc')
def landing_usa_computer_science50():
    return render_template('landing_usa.html', data="computer science classes greenville sc")
@app.route('/computer-science-classes-washington-dc')
def landing_usa_computer_science51():
    return render_template('landing_usa.html', data="computer science classes washington dc")
@app.route('/computer-science-classes-louisville-ky')
def landing_usa_computer_science52():
    return render_template('landing_usa.html', data="computer science classes louisville ky")
@app.route('/computer-science-classes-in-knoxville-tn')
def landing_usa_computer_science53():
    return render_template('landing_usa.html', data="computer science classes in knoxville tn")
@app.route('/computer-science-classes-colorado-springs')
def landing_usa_computer_science54():
    return render_template('landing_usa.html', data="computer science classes colorado springs")
@app.route('/computer-science-classes-memphis-tn')
def landing_usa_computer_science55():
    return render_template('landing_usa.html', data="computer science classes memphis tn")
@app.route('/computer-science-classes-phoenix')
def landing_usa_computer_science56():
    return render_template('landing_usa.html', data="computer science classes phoenix")
@app.route('/computer-science-classes-boston-ma')
def landing_usa_computer_science57():
    return render_template('landing_usa.html', data="computer science classes boston ma")
@app.route('/computer-science-classes-st-louis-mo')
def landing_usa_computer_science58():
    return render_template('landing_usa.html', data="computer science classes st louis mo")
@app.route('/computer-science-classes-atlanta-ga')
def landing_usa_computer_science59():
    return render_template('landing_usa.html', data="computer science classes atlanta ga")

@app.route('/computer-science-classes-baton-rouge')
def landing_usa_computer_science60():
    return render_template('landing_usa.html', data="computer science classes baton rouge")
@app.route('/computer-science-classes-in-houston-texas')
def landing_usa_computer_science61():
    return render_template('landing_usa.html', data="computer science classes in houston texas")
@app.route('/computer-science-classes-san-antonio')
def landing_usa_computer_science62():
    return render_template('landing_usa.html', data="computer science classes san antonio")
@app.route('/computer-science-classes-houston-tx')
def landing_usa_computer_science63():
    return render_template('landing_usa.html', data="computer science classes houston tx")
@app.route('/computer-science-classes-dallas-tx')
def landing_usa_computer_science64():
    return render_template('landing_usa.html', data=" ")
@app.route('/computer-science-classes-portland-oregon')
def landing_usa_computer_science65():
    return render_template('landing_usa.html', data="computer science classes portland oregon")
@app.route('/computer-science-classes-queens-ny')
def landing_usa_computer_science66():
    return render_template('landing_usa.html', data="computer science classes queens ny")
@app.route('/computer-science-classes-cleveland-ohio')
def landing_usa_computer_science67():
    return render_template('landing_usa.html', data="computer science classes cleveland ohio")
@app.route('/computer-science-classes-bronx-ny')
def landing_usa_computer_science68():
    return render_template('landing_usa.html', data="computer science classes bronx ny")
@app.route('/computer-science-classes-tampa')
def landing_usa_computer_science69():
    return render_template('landing_usa.html', data="computer science classes tampa")

@app.route('/computer-science-classes-albany-ny')
def landing_usa_computer_science70():
    return render_template('landing_usa.html', data="computer science classes albany ny")
@app.route('/computer-science-classes-tampa-fl')
def landing_usa_computer_science71():
    return render_template('landing_usa.html', data="computer science classes tampa fl")
@app.route('/computer-science-classes-brooklyn-ny')
def landing_usa_computer_science72():
    return render_template('landing_usa.html', data="computer science classes brooklyn ny")
@app.route('/computer-science-classes-dc')
def landing_usa_computer_science73():
    return render_template('landing_usa.html', data="computer science classes dc")
@app.route('/computer-science-classes-knoxville-tne')
def landing_usa_computer_science74():
    return render_template('landing_usa.html', data="computer science classes knoxville tn")
@app.route('/computer-science-classes-raleigh-nc')
def landing_usa_computer_science75():
    return render_template('landing_usa.html', data="computer science classes raleigh nc")
@app.route('/computer-science-classes-staten-island-ny')
def landing_usa_computer_science76():
    return render_template('landing_usa.html', data="computer science classes staten island ny")
@app.route('/computer-science-classes-anchorage-ak')
def landing_usa_computer_science77():
    return render_template('landing_usa.html', data="computer science classes anchorage ak")
@app.route('/computer-science-classes-courses')
def landing_usa_computer_science78():
    return render_template('landing_usa.html', data="computer science classes courses")
@app.route('/computer-science-classes-sacramento-ca')
def landing_usa_computer_science79():
    return render_template('landing_usa.html', data="computer science classes sacramento ca")

@app.route('/computer-science-classes-chicago-il')
def landing_usa_computer_science80():
    return render_template('landing_usa.html', data="computer science classes chicago il")
@app.route('/computer-science-classes-miami-fl')
def landing_usa_computer_science81():
    return render_template('landing_usa.html', data="computer science classes miami fl")
@app.route('/computer-science-classes-bakersfield-ca')
def landing_usa_computer_science82():
    return render_template('landing_usa.html', data="computer science classes bakersfield ca")
@app.route('/computer-science-classes-baltimore-md')
def landing_usa_computer_science83():
    return render_template('landing_usa.html', data="computer science classes baltimore md")
@app.route('/computer-science-classes-new-york')
def landing_usa_computer_science84():
    return render_template('landing_usa.html', data="computer science classes new york")
@app.route('/computer-science-classes-las-vegas-nv')
def landing_usa_computer_science85():
    return render_template('landing_usa.html', data="computer science classes las vegas nv")
@app.route('/computer-science-classes-san-diego-ca')
def landing_usa_computer_science86():
    return render_template('landing_usa.html', data="computer science classes san diego ca")
@app.route('/computer-science-classes-austin-texas')
def landing_usa_computer_science87():
    return render_template('landing_usa.html', data="computer science classes austin texas")
@app.route('/computer-science-classes-milwaukee')
def landing_usa_computer_science88():
    return render_template('landing_usa.html', data="computer science classes milwaukee")
@app.route('/computer-science-classes-reno-nv')
def landing_usa_computer_science89():
    return render_template('landing_usa.html', data="computer science classes reno nv")

@app.route('/computer-science-classes-oklahoma-city')
def landing_usa_computer_science90():
    return render_template('landing_usa.html', data="computer science classes oklahoma city")
@app.route('/computer-science-classes-erie-pa')
def landing_usa_computer_science91():
    return render_template('landing_usa.html', data="computer science classes erie pa")
@app.route('/computer-science-classes-for-adults-in-chicago')
def landing_usa_computer_science92():
    return render_template('landing_usa.html', data="computer science classes for adults in chicago")
#############################################Coding Bootcamps USA#############
@app.route('/coding-boot-camp-nyc')
def landing_usa_coding_boot1():
    return render_template('landing_usa.html', data="coding boot camp nyc ")
@app.route('/coding-boot-camp-near-me')
def landing_usa_coding_boot2():
    return render_template('landing_usa.html', data="coding-boot camp near me ")
@app.route('/coding-boot-camp-in-chicago')
def landing_usa_coding_boot3():
    return render_template('landing_usa.html', data="coding boot camp in chicago ")
@app.route('/coding-boot-camp-in-philadelphia')
def landing_usa_coding_boot4():
    return render_template('landing_usa.html', data="coding boot camp in philadelphia ")
@app.route('/coding-boot-camp-in-houston')
def landing_usa_coding_boot5():
    return render_template('landing_usa.html', data="coding boot camp in houston")
@app.route('/coding-boot-camp-in-dc')
def landing_usa_coding_boot6():
    return render_template('landing_usa.html', data="coding boot camp in dc")
@app.route('/coding-boot-camp-for-adults-in-nyc')
def landing_usa_coding_boot7():
    return render_template('landing_usa.html', data="coding boot camp for adults in nyc")
@app.route('/coding-boot-camp-san-diego')
def landing_usa_coding_boot8():
    return render_template('landing_usa.html', data="coding boot camp san diego")
@app.route('/coding-boot-camp-nj')
def landing_usa_coding_boot9():
    return render_template('landing_usa.html', data="coding boot camp nj")

@app.route('/coding-boot-camp-in-las-vegas')
def landing_usa_coding_boot10():
    return render_template('landing_usa.html', data="coding boot camp in las vegas")
@app.route('/coding-boot-camp-in-nyc')
def landing_usa_coding_boot11():
    return render_template('landing_usa.html', data="coding boot camp in nyc")
@app.route('/coding-boot-camp-buffalo-ny')
def landing_usa_coding_boot12():
    return render_template('landing_usa.html', data="coding boot camp buffalo ny")
@app.route('/coding-boot-camp-los-angeles')
def landing_usa_coding_boot13():
    return render_template('landing_usa.html', data="coding boot camp los angeles")
@app.route('/coding-boot-camp-in-columbus-ohio')
def landing_usa_coding_boot14():
    return render_template('landing_usa.html', data="coding boot camp in columbus ohio")
@app.route('/coding-boot-camp-charlotte-nc')
def landing_usa_coding_boot15():
    return render_template('landing_usa.html', data="coding boot camp charlotte nc")
@app.route('/coding-boot-camp-philadelphia')
def landing_usa_coding_boot16():
    return render_template('landing_usa.html', data="coding boot camp philadelphia")
@app.route('/coding-boot-camp-seattle')
def landing_usa_coding_boot17():
    return render_template('landing_usa.html', data="coding boot camp seattle")
@app.route('/coding-boot-camp-minneapolis')
def landing_usa_coding_boot18():
    return render_template('landing_usa.html', data="coding boot camp minneapolis")
@app.route('/coding-boot-camp-austin')
def landing_usa_coding_boot19():
    return render_template('landing_usa.html', data="coding boot camp austin")

@app.route('/coding-boot-camp-in-dallas-tx')
def landing_usa_coding_boot20():
    return render_template('landing_usa.html', data="coding boot camp in dallas tx")
@app.route('/coding-boot-camp-in-ri')
def landing_usa_coding_boot21():
    return render_template('landing_usa.html', data="coding boot camp in ri")
@app.route('/coding-boot-camp-in-san-antonio-tx')
def landing_usa_coding_boot22():
    return render_template('landing_usa.html', data="coding boot camp in san antonio tx")
@app.route('/coding-boot-camp-new-orleans')
def landing_usa_coding_boot23():
    return render_template('landing_usa.html', data="coding boot camp new orleans")
@app.route('/coding-boot-camp-nashville-tn')
def landing_usa_coding_boot24():
    return render_template('landing_usa.html', data="coding boot camp nashville tn")
@app.route('/coding-boot-camp-boston')
def landing_usa_coding_boot25():
    return render_template('landing_usa.html', data="coding boot camp boston")
@app.route('/coding-boot-camp-denver')
def landing_usa_coding_boot26():
    return render_template('landing_usa.html', data="coding boot camp denver")
@app.route('/coding-boot-camp-brooklyn')
def landing_usa_coding_boot27():
    return render_template('landing_usa.html', data="coding boot camp brooklyn")
@app.route('/coding-boot-camp-miami')
def landing_usa_coding_boot28():
    return render_template('landing_usa.html', data="coding boot camp miami")
@app.route('/coding-boot-camp-houston')
def landing_usa_coding_boot29():
    return render_template('landing_usa.html', data="coding boot camp houston")

@app.route('/coding-boot-camp-bronx')
def landing_usa_coding_boot30():
    return render_template('landing_usa.html', data="coding boot camp bronx")
@app.route('/coding-boot-camp-birmingham-al')
def landing_usa_coding_boot31():
    return render_template('landing_usa.html', data="coding boot camp birmingham al")
@app.route('/coding-boot-camp-san-francisco')
def landing_usa_coding_boot32():
    return render_template('landing_usa.html', data="coding boot camp san francisco")
@app.route('/coding-boot-camp-in-atlanta-ga')
def landing_usa_coding_boot33():
    return render_template('landing_usa.html', data="coding boot camp in atlanta ga")
@app.route('/coding-boot-camp-phoenix-az')
def landing_usa_coding_boot34():
    return render_template('landing_usa.html', data="coding boot camp phoenix az")
@app.route('/coding-boot-camp-richmond-va')
def landing_usa_coding_boot35():
    return render_template('landing_usa.html', data="coding boot camp richmond va")
@app.route('/coding-boot-camp-mn')
def landing_usa_coding_boot36():
    return render_template('landing_usa.html', data="coding boot camp mn")
@app.route('/coding-boot-camp-san-antonio-tx')
def landing_usa_coding_boot37():
    return render_template('landing_usa.html', data="coding boot camp san antonio tx")
@app.route('/coding-boot-camp-sacramento')
def landing_usa_coding_boot38():
    return render_template('landing_usa.html', data="coding boot camp sacramento")
@app.route('/coding-boot-camp-austin-tx')
def landing_usa_coding_boot39():
    return render_template('landing_usa.html', data="coding boot camp austin tx")

@app.route('/coding-boot-camp-rochester-ny')
def landing_usa_coding_boot40():
    return render_template('landing_usa.html', data="coding boot camp rochester ny")
@app.route('/coding-boot-camp-in-charlotte-nc')
def landing_usa_coding_boot41():
    return render_template('landing_usa.html', data="coding boot camp in charlotte nc")
@app.route('/coding-boot-camp-tucson')
def landing_usa_coding_boot42():
    return render_template('landing_usa.html', data="coding boot camp tucson")
@app.route('/coding-boot-camp-pittsburgh')
def landing_usa_coding_boot43():
    return render_template('landing_usa.html', data="coding boot camp pittsburgh")
@app.route('/coding-boot-camp-in-detroit')
def landing_usa_coding_boot44():
    return render_template('landing_usa.html', data="coding boot camp in detroit")
@app.route('/coding-boot-camp-kansas-city')
def landing_usa_coding_boot45():
    return render_template('landing_usa.html', data="coding boot camp kansas city")
@app.route('/coding-boot-camp-detroit')
def landing_usa_coding_boot46():
    return render_template('landing_usa.html', data="coding boot camp detroit")
@app.route('/coding-boot-camp-on-the-internet')
def landing_usa_coding_boot47():
    return render_template('landing_usa.html', data=" ")
@app.route('/teach-english-abroad-without-tefl-or-degree')
def landing_usa_coding_boot48():
    return render_template('landing_usa.html', data="coding boot camp on the internet")
@app.route('/coding-boot-camp-mesa-az')
def landing_usa_coding_boot49():
    return render_template('landing_usa.html', data="coding boot camp mesa az")

@app.route('/coding-boot-camp-greenville-sc')
def landing_usa_coding_boot50():
    return render_template('landing_usa.html', data="coding boot camp greenville sc")
@app.route('/coding-boot-camp-washington-dc')
def landing_usa_coding_boot51():
    return render_template('landing_usa.html', data="coding boot camp washington dc")
@app.route('/coding-boot-camp-louisville-ky')
def landing_usa_coding_boot52():
    return render_template('landing_usa.html', data="coding boot camp louisville ky")
@app.route('/coding-boot-camp-in-knoxville-tn')
def landing_usa_coding_boot53():
    return render_template('landing_usa.html', data="coding boot camp in knoxville tn")
@app.route('/coding-boot-camp-colorado-springs')
def landing_usa_coding_boot54():
    return render_template('landing_usa.html', data="coding boot camp colorado springs")
@app.route('/coding-boot-camp-memphis-tn')
def landing_usa_coding_boot55():
    return render_template('landing_usa.html', data="coding boot camp memphis tn")
@app.route('/coding-boot-camp-phoenix')
def landing_usa_coding_boot56():
    return render_template('landing_usa.html', data="coding boot camp phoenix")
@app.route('/coding-boot-camp-boston-ma')
def landing_usa_coding_boot57():
    return render_template('landing_usa.html', data="coding boot camp boston ma")
@app.route('/coding-boot-camp-st-louis-mo')
def landing_usa_coding_boot58():
    return render_template('landing_usa.html', data="coding boot camp st louis mo")
@app.route('/coding-boot-camp-atlanta-ga')
def landing_usa_coding_boot59():
    return render_template('landing_usa.html', data="coding boot camp atlanta ga")

@app.route('/coding-boot-camp-baton-rouge')
def landing_usa_coding_boot60():
    return render_template('landing_usa.html', data="coding boot camp baton rouge")
@app.route('/coding-boot-camp-in-houston-texas')
def landing_usa_coding_boot61():
    return render_template('landing_usa.html', data="coding boot camp in houston texas")
@app.route('/coding-boot-camp-san-antonio')
def landing_usa_coding_boot62():
    return render_template('landing_usa.html', data="coding boot camp san antonio")
@app.route('/coding-boot-camp-houston-tx')
def landing_usa_coding_boot63():
    return render_template('landing_usa.html', data="coding boot camp houston tx")
@app.route('/coding-boot-camp-dallas-tx')
def landing_usa_coding_boot64():
    return render_template('landing_usa.html', data=" ")
@app.route('/coding-boot-camp-portland-oregon')
def landing_usa_coding_boot65():
    return render_template('landing_usa.html', data="coding boot camp portland oregon")
@app.route('/coding-boot-camp-queens-ny')
def landing_usa_coding_boot66():
    return render_template('landing_usa.html', data="coding boot camp queens ny")
@app.route('/coding-boot-camp-cleveland-ohio')
def landing_usa_coding_boot67():
    return render_template('landing_usa.html', data="coding boot camp cleveland ohio")
@app.route('/coding-boot-camp-bronx-ny')
def landing_usa_coding_boot68():
    return render_template('landing_usa.html', data="coding boot camp bronx ny")
@app.route('/coding-boot-camp-tampa')
def landing_usa_coding_boot69():
    return render_template('landing_usa.html', data="coding boot camp tampa")

@app.route('/coding-boot-camp-albany-ny')
def landing_usa_coding_boot70():
    return render_template('landing_usa.html', data="coding boot camp albany ny")
@app.route('/coding-boot-camp-tampa-fl')
def landing_usa_coding_boot71():
    return render_template('landing_usa.html', data="coding boot camp tampa fl")
@app.route('/coding-boot-camp-brooklyn-ny')
def landing_usa_coding_boot72():
    return render_template('landing_usa.html', data="coding boot camp brooklyn ny")
@app.route('/coding-boot-camp-dc')
def landing_usa_coding_boot73():
    return render_template('landing_usa.html', data="coding boot camp dc")
@app.route('/coding-boot-camp-knoxville-tne')
def landing_usa_coding_boot74():
    return render_template('landing_usa.html', data="coding boot camp knoxville tn")
@app.route('/coding-boot-camp-raleigh-nc')
def landing_usa_coding_boot75():
    return render_template('landing_usa.html', data="coding boot camp raleigh nc")
@app.route('/coding-boot-camp-staten-island-ny')
def landing_usa_coding_boot76():
    return render_template('landing_usa.html', data="coding boot camp staten island ny")
@app.route('/coding-boot-camp-anchorage-ak')
def landing_usa_coding_boot77():
    return render_template('landing_usa.html', data="coding boot camp anchorage ak")
@app.route('/coding-boot-camp-courses')
def landing_usa_coding_boot78():
    return render_template('landing_usa.html', data="coding boot camp courses")
@app.route('/coding-boot-camp-sacramento-ca')
def landing_usa_coding_boot79():
    return render_template('landing_usa.html', data="coding boot camp sacramento ca")

@app.route('/coding-boot-camp-chicago-il')
def landing_usa_coding_boot80():
    return render_template('landing_usa.html', data="coding boot camp chicago il")
@app.route('/coding-boot-camp-miami-fl')
def landing_usa_coding_boot81():
    return render_template('landing_usa.html', data="coding boot camp miami fl")
@app.route('/coding-boot-camp-bakersfield-ca')
def landing_usa_coding_boot82():
    return render_template('landing_usa.html', data="coding boot camp bakersfield ca")
@app.route('/coding-boot-camp-baltimore-md')
def landing_usa_coding_boot83():
    return render_template('landing_usa.html', data="coding boot camp baltimore md")
@app.route('/coding-boot-camp-new-york')
def landing_usa_coding_boot84():
    return render_template('landing_usa.html', data="coding boot camp new york")
@app.route('/coding-boot-camp-las-vegas-nv')
def landing_usa_coding_boot85():
    return render_template('landing_usa.html', data="coding boot camp las vegas nv")
@app.route('/coding-boot-camp-san-diego-ca')
def landing_usa_coding_boot86():
    return render_template('landing_usa.html', data="coding boot camp san diego ca")
@app.route('/coding-boot-camp-austin-texas')
def landing_usa_coding_boot87():
    return render_template('landing_usa.html', data="coding boot camp austin texas")
@app.route('/coding-boot-camp-milwaukee')
def landing_usa_coding_boot88():
    return render_template('landing_usa.html', data="coding boot camp milwaukee")
@app.route('/coding-boot-camp-reno-nv')
def landing_usa_coding_boot89():
    return render_template('landing_usa.html', data="coding boot camp reno nv")

@app.route('/coding-boot-camp-oklahoma-city')
def landing_usa_coding_boot90():
    return render_template('landing_usa.html', data="coding boot camp oklahoma city")
@app.route('/coding-boot-camp-erie-pa')
def landing_usa_coding_boot91():
    return render_template('landing_usa.html', data="coding boot camp erie pa")
@app.route('/coding-boot-camp-for-adults-in-chicago')
def landing_usa_coding_boot92():
    return render_template('landing_usa.html', data="coding boot camp for adults in chicago")

#####################pmp bootcamp #####################
@app.route('/pmp-boot-camp-nyc')
def landing_usa_pmp_boot1():
    return render_template('landing_usa.html', data="pmp boot camp nyc ")
@app.route('/pmp-boot-camp-near-me')
def landing_usa_pmp_boot2():
    return render_template('landing_usa.html', data="pmp-boot camp near me ")
@app.route('/pmp-boot-camp-in-chicago')
def landing_usa_pmp_boot3():
    return render_template('landing_usa.html', data="pmp boot camp in chicago ")
@app.route('/pmp-boot-camp-in-philadelphia')
def landing_usa_pmp_boot4():
    return render_template('landing_usa.html', data="pmp boot camp in philadelphia ")
@app.route('/pmp-boot-camp-in-houston')
def landing_usa_pmp_boot5():
    return render_template('landing_usa.html', data="pmp boot camp in houston")
@app.route('/pmp-boot-camp-in-dc')
def landing_usa_pmp_boot6():
    return render_template('landing_usa.html', data="pmp boot camp in dc")
@app.route('/pmp-boot-camp-for-adults-in-nyc')
def landing_usa_pmp_boot7():
    return render_template('landing_usa.html', data="pmp boot camp for adults in nyc")
@app.route('/pmp-boot-camp-san-diego')
def landing_usa_pmp_boot8():
    return render_template('landing_usa.html', data="pmp boot camp san diego")
@app.route('/pmp-boot-camp-nj')
def landing_usa_pmp_boot9():
    return render_template('landing_usa.html', data="pmp boot camp nj")

@app.route('/pmp-boot-camp-in-las-vegas')
def landing_usa_pmp_boot10():
    return render_template('landing_usa.html', data="pmp boot camp in las vegas")
@app.route('/pmp-boot-camp-in-nyc')
def landing_usa_pmp_boot11():
    return render_template('landing_usa.html', data="pmp boot camp in nyc")
@app.route('/pmp-boot-camp-buffalo-ny')
def landing_usa_pmp_boot12():
    return render_template('landing_usa.html', data="pmp boot camp buffalo ny")
@app.route('/pmp-boot-camp-los-angeles')
def landing_usa_pmp_boot13():
    return render_template('landing_usa.html', data="pmp boot camp los angeles")
@app.route('/pmp-boot-camp-in-columbus-ohio')
def landing_usa_pmp_boot14():
    return render_template('landing_usa.html', data="pmp boot camp in columbus ohio")
@app.route('/pmp-boot-camp-charlotte-nc')
def landing_usa_pmp_boot15():
    return render_template('landing_usa.html', data="pmp boot camp charlotte nc")
@app.route('/pmp-boot-camp-philadelphia')
def landing_usa_pmp_boot16():
    return render_template('landing_usa.html', data="pmp boot camp philadelphia")
@app.route('/pmp-boot-camp-seattle')
def landing_usa_pmp_boot17():
    return render_template('landing_usa.html', data="pmp boot camp seattle")
@app.route('/pmp-boot-camp-minneapolis')
def landing_usa_pmp_boot18():
    return render_template('landing_usa.html', data="pmp boot camp minneapolis")
@app.route('/pmp-boot-camp-austin')
def landing_usa_pmp_boot19():
    return render_template('landing_usa.html', data="pmp boot camp austin")

@app.route('/pmp-boot-camp-in-dallas-tx')
def landing_usa_pmp_boot20():
    return render_template('landing_usa.html', data="pmp boot camp in dallas tx")
@app.route('/pmp-boot-camp-in-ri')
def landing_usa_pmp_boot21():
    return render_template('landing_usa.html', data="pmp boot camp in ri")
@app.route('/pmp-boot-camp-in-san-antonio-tx')
def landing_usa_pmp_boot22():
    return render_template('landing_usa.html', data="pmp boot camp in san antonio tx")
@app.route('/pmp-boot-camp-new-orleans')
def landing_usa_pmp_boot23():
    return render_template('landing_usa.html', data="pmp boot camp new orleans")
@app.route('/pmp-boot-camp-nashville-tn')
def landing_usa_pmp_boot24():
    return render_template('landing_usa.html', data="pmp boot camp nashville tn")
@app.route('/pmp-boot-camp-boston')
def landing_usa_pmp_boot25():
    return render_template('landing_usa.html', data="pmp boot camp boston")
@app.route('/pmp-boot-camp-denver')
def landing_usa_pmp_boot26():
    return render_template('landing_usa.html', data="pmp boot camp denver")
@app.route('/pmp-boot-camp-brooklyn')
def landing_usa_pmp_boot27():
    return render_template('landing_usa.html', data="pmp boot camp brooklyn")
@app.route('/pmp-boot-camp-miami')
def landing_usa_pmp_boot28():
    return render_template('landing_usa.html', data="pmp boot camp miami")
@app.route('/pmp-boot-camp-houston')
def landing_usa_pmp_boot29():
    return render_template('landing_usa.html', data="pmp boot camp houston")

@app.route('/pmp-boot-camp-bronx')
def landing_usa_pmp_boot30():
    return render_template('landing_usa.html', data="pmp boot camp bronx")
@app.route('/pmp-boot-camp-birmingham-al')
def landing_usa_pmp_boot31():
    return render_template('landing_usa.html', data="pmp boot camp birmingham al")
@app.route('/pmp-boot-camp-san-francisco')
def landing_usa_pmp_boot32():
    return render_template('landing_usa.html', data="pmp boot camp san francisco")
@app.route('/pmp-boot-camp-in-atlanta-ga')
def landing_usa_pmp_boot33():
    return render_template('landing_usa.html', data="pmp boot camp in atlanta ga")
@app.route('/pmp-boot-camp-phoenix-az')
def landing_usa_pmp_boot34():
    return render_template('landing_usa.html', data="pmp boot camp phoenix az")
@app.route('/pmp-boot-camp-richmond-va')
def landing_usa_pmp_boot35():
    return render_template('landing_usa.html', data="pmp boot camp richmond va")
@app.route('/pmp-boot-camp-mn')
def landing_usa_pmp_boot36():
    return render_template('landing_usa.html', data="pmp boot camp mn")
@app.route('/pmp-boot-camp-san-antonio-tx')
def landing_usa_pmp_boot37():
    return render_template('landing_usa.html', data="pmp boot camp san antonio tx")
@app.route('/pmp-boot-camp-sacramento')
def landing_usa_pmp_boot38():
    return render_template('landing_usa.html', data="pmp boot camp sacramento")
@app.route('/pmp-boot-camp-austin-tx')
def landing_usa_pmp_boot39():
    return render_template('landing_usa.html', data="pmp boot camp austin tx")

@app.route('/pmp-boot-camp-rochester-ny')
def landing_usa_pmp_boot40():
    return render_template('landing_usa.html', data="pmp boot camp rochester ny")
@app.route('/pmp-boot-camp-in-charlotte-nc')
def landing_usa_pmp_boot41():
    return render_template('landing_usa.html', data="pmp boot camp in charlotte nc")
@app.route('/pmp-boot-camp-tucson')
def landing_usa_pmp_boot42():
    return render_template('landing_usa.html', data="pmp boot camp tucson")
@app.route('/pmp-boot-camp-pittsburgh')
def landing_usa_pmp_boot43():
    return render_template('landing_usa.html', data="pmp boot camp pittsburgh")
@app.route('/pmp-boot-camp-in-detroit')
def landing_usa_pmp_boot44():
    return render_template('landing_usa.html', data="pmp boot camp in detroit")
@app.route('/pmp-boot-camp-kansas-city')
def landing_usa_pmp_boot45():
    return render_template('landing_usa.html', data="pmp boot camp kansas city")
@app.route('/pmp-boot-camp-detroit')
def landing_usa_pmp_boot46():
    return render_template('landing_usa.html', data="pmp boot camp detroit")
@app.route('/pmp-boot-camp-on-the-internet')
def landing_usa_pmp_boot47():
    return render_template('landing_usa.html', data=" ")
@app.route('/teach-english-abroad-without-tefl-or-degree')
def landing_usa_pmp_boot48():
    return render_template('landing_usa.html', data="pmp boot camp on the internet")
@app.route('/pmp-boot-camp-mesa-az')
def landing_usa_pmp_boot49():
    return render_template('landing_usa.html', data="pmp boot camp mesa az")

@app.route('/pmp-boot-camp-greenville-sc')
def landing_usa_pmp_boot50():
    return render_template('landing_usa.html', data="pmp boot camp greenville sc")
@app.route('/pmp-boot-camp-washington-dc')
def landing_usa_pmp_boot51():
    return render_template('landing_usa.html', data="pmp boot camp washington dc")
@app.route('/pmp-boot-camp-louisville-ky')
def landing_usa_pmp_boot52():
    return render_template('landing_usa.html', data="pmp boot camp louisville ky")
@app.route('/pmp-boot-camp-in-knoxville-tn')
def landing_usa_pmp_boot53():
    return render_template('landing_usa.html', data="pmp boot camp in knoxville tn")
@app.route('/pmp-boot-camp-colorado-springs')
def landing_usa_pmp_boot54():
    return render_template('landing_usa.html', data="pmp boot camp colorado springs")
@app.route('/pmp-boot-camp-memphis-tn')
def landing_usa_pmp_boot55():
    return render_template('landing_usa.html', data="pmp boot camp memphis tn")
@app.route('/pmp-boot-camp-phoenix')
def landing_usa_pmp_boot56():
    return render_template('landing_usa.html', data="pmp boot camp phoenix")
@app.route('/pmp-boot-camp-boston-ma')
def landing_usa_pmp_boot57():
    return render_template('landing_usa.html', data="pmp boot camp boston ma")
@app.route('/pmp-boot-camp-st-louis-mo')
def landing_usa_pmp_boot58():
    return render_template('landing_usa.html', data="pmp boot camp st louis mo")
@app.route('/pmp-boot-camp-atlanta-ga')
def landing_usa_pmp_boot59():
    return render_template('landing_usa.html', data="pmp boot camp atlanta ga")

@app.route('/pmp-boot-camp-baton-rouge')
def landing_usa_pmp_boot60():
    return render_template('landing_usa.html', data="pmp boot camp baton rouge")
@app.route('/pmp-boot-camp-in-houston-texas')
def landing_usa_pmp_boot61():
    return render_template('landing_usa.html', data="pmp boot camp in houston texas")
@app.route('/pmp-boot-camp-san-antonio')
def landing_usa_pmp_boot62():
    return render_template('landing_usa.html', data="pmp boot camp san antonio")
@app.route('/pmp-boot-camp-houston-tx')
def landing_usa_pmp_boot63():
    return render_template('landing_usa.html', data="pmp boot camp houston tx")
@app.route('/pmp-boot-camp-dallas-tx')
def landing_usa_pmp_boot64():
    return render_template('landing_usa.html', data=" ")
@app.route('/pmp-boot-camp-portland-oregon')
def landing_usa_pmp_boot65():
    return render_template('landing_usa.html', data="pmp boot camp portland oregon")
@app.route('/pmp-boot-camp-queens-ny')
def landing_usa_pmp_boot66():
    return render_template('landing_usa.html', data="pmp boot camp queens ny")
@app.route('/pmp-boot-camp-cleveland-ohio')
def landing_usa_pmp_boot67():
    return render_template('landing_usa.html', data="pmp boot camp cleveland ohio")
@app.route('/pmp-boot-camp-bronx-ny')
def landing_usa_pmp_boot68():
    return render_template('landing_usa.html', data="pmp boot camp bronx ny")
@app.route('/pmp-boot-camp-tampa')
def landing_usa_pmp_boot69():
    return render_template('landing_usa.html', data="pmp boot camp tampa")

@app.route('/pmp-boot-camp-albany-ny')
def landing_usa_pmp_boot70():
    return render_template('landing_usa.html', data="pmp boot camp albany ny")
@app.route('/pmp-boot-camp-tampa-fl')
def landing_usa_pmp_boot71():
    return render_template('landing_usa.html', data="pmp boot camp tampa fl")
@app.route('/pmp-boot-camp-brooklyn-ny')
def landing_usa_pmp_boot72():
    return render_template('landing_usa.html', data="pmp boot camp brooklyn ny")
@app.route('/pmp-boot-camp-dc')
def landing_usa_pmp_boot73():
    return render_template('landing_usa.html', data="pmp boot camp dc")
@app.route('/pmp-boot-camp-knoxville-tne')
def landing_usa_pmp_boot74():
    return render_template('landing_usa.html', data="pmp boot camp knoxville tn")
@app.route('/pmp-boot-camp-raleigh-nc')
def landing_usa_pmp_boot75():
    return render_template('landing_usa.html', data="pmp boot camp raleigh nc")
@app.route('/pmp-boot-camp-staten-island-ny')
def landing_usa_pmp_boot76():
    return render_template('landing_usa.html', data="pmp boot camp staten island ny")
@app.route('/pmp-boot-camp-anchorage-ak')
def landing_usa_pmp_boot77():
    return render_template('landing_usa.html', data="pmp boot camp anchorage ak")
@app.route('/pmp-boot-camp-courses')
def landing_usa_pmp_boot78():
    return render_template('landing_usa.html', data="pmp boot camp courses")
@app.route('/pmp-boot-camp-sacramento-ca')
def landing_usa_pmp_boot79():
    return render_template('landing_usa.html', data="pmp boot camp sacramento ca")

@app.route('/pmp-boot-camp-chicago-il')
def landing_usa_pmp_boot80():
    return render_template('landing_usa.html', data="pmp boot camp chicago il")
@app.route('/pmp-boot-camp-miami-fl')
def landing_usa_pmp_boot81():
    return render_template('landing_usa.html', data="pmp boot camp miami fl")
@app.route('/pmp-boot-camp-bakersfield-ca')
def landing_usa_pmp_boot82():
    return render_template('landing_usa.html', data="pmp boot camp bakersfield ca")
@app.route('/pmp-boot-camp-baltimore-md')
def landing_usa_pmp_boot83():
    return render_template('landing_usa.html', data="pmp boot camp baltimore md")
@app.route('/pmp-boot-camp-new-york')
def landing_usa_pmp_boot84():
    return render_template('landing_usa.html', data="pmp boot camp new york")
@app.route('/pmp-boot-camp-las-vegas-nv')
def landing_usa_pmp_boot85():
    return render_template('landing_usa.html', data="pmp boot camp las vegas nv")
@app.route('/pmp-boot-camp-san-diego-ca')
def landing_usa_pmp_boot86():
    return render_template('landing_usa.html', data="pmp boot camp san diego ca")
@app.route('/pmp-boot-camp-austin-texas')
def landing_usa_pmp_boot87():
    return render_template('landing_usa.html', data="pmp boot camp austin texas")
@app.route('/pmp-boot-camp-milwaukee')
def landing_usa_pmp_boot88():
    return render_template('landing_usa.html', data="pmp boot camp milwaukee")
@app.route('/pmp-boot-camp-reno-nv')
def landing_usa_pmp_boot89():
    return render_template('landing_usa.html', data="pmp boot camp reno nv")

@app.route('/pmp-boot-camp-oklahoma-city')
def landing_usa_pmp_boot90():
    return render_template('landing_usa.html', data="pmp boot camp oklahoma city")
@app.route('/pmp-boot-camp-erie-pa')
def landing_usa_pmp_boot91():
    return render_template('landing_usa.html', data="pmp boot camp erie pa")
@app.route('/pmp-boot-camp-for-adults-in-chicago')
def landing_usa_pmp_boot92():
    return render_template('landing_usa.html', data="pmp boot camp for adults in chicago")


#################################################################Whole foods cooking classes ###############
@app.route('/whole-foods-cooking-classes-nyc')
def landing_usa_whole_foods_cooking1():
    return render_template('landing_usa.html', data="whole foods cooking classes nyc ")
@app.route('/whole-foods-cooking-classes-near-me')
def landing_usa_whole_foods_cooking2():
    return render_template('landing_usa.html', data="whole-foods-cooking classes near me ")
@app.route('/whole-foods-cooking-classes-in-chicago')
def landing_usa_whole_foods_cooking3():
    return render_template('landing_usa.html', data="whole foods cooking classes in chicago ")
@app.route('/whole-foods-cooking-classes-in-philadelphia')
def landing_usa_whole_foods_cooking4():
    return render_template('landing_usa.html', data="whole foods cooking classes in philadelphia ")
@app.route('/whole-foods-cooking-classes-in-houston')
def landing_usa_whole_foods_cooking5():
    return render_template('landing_usa.html', data="whole foods cooking classes in houston")
@app.route('/whole-foods-cooking-classes-in-dc')
def landing_usa_whole_foods_cooking6():
    return render_template('landing_usa.html', data="whole foods cooking classes in dc")
@app.route('/whole-foods-cooking-classes-for-adults-in-nyc')
def landing_usa_whole_foods_cooking7():
    return render_template('landing_usa.html', data="whole foods cooking classes for adults in nyc")
@app.route('/whole-foods-cooking-classes-san-diego')
def landing_usa_whole_foods_cooking8():
    return render_template('landing_usa.html', data="whole foods cooking classes san diego")
@app.route('/whole-foods-cooking-classes-nj')
def landing_usa_whole_foods_cooking9():
    return render_template('landing_usa.html', data="whole foods cooking classes nj")

@app.route('/whole-foods-cooking-classes-in-las-vegas')
def landing_usa_whole_foods_cooking10():
    return render_template('landing_usa.html', data="whole foods cooking classes in las vegas")
@app.route('/whole-foods-cooking-classes-in-nyc')
def landing_usa_whole_foods_cooking11():
    return render_template('landing_usa.html', data="whole foods cooking classes in nyc")
@app.route('/whole-foods-cooking-classes-buffalo-ny')
def landing_usa_whole_foods_cooking12():
    return render_template('landing_usa.html', data="whole foods cooking classes buffalo ny")
@app.route('/whole-foods-cooking-classes-los-angeles')
def landing_usa_whole_foods_cooking13():
    return render_template('landing_usa.html', data="whole foods cooking classes los angeles")
@app.route('/whole-foods-cooking-classes-in-columbus-ohio')
def landing_usa_whole_foods_cooking14():
    return render_template('landing_usa.html', data="whole foods cooking classes in columbus ohio")
@app.route('/whole-foods-cooking-classes-charlotte-nc')
def landing_usa_whole_foods_cooking15():
    return render_template('landing_usa.html', data="whole foods cooking classes charlotte nc")
@app.route('/whole-foods-cooking-classes-philadelphia')
def landing_usa_whole_foods_cooking16():
    return render_template('landing_usa.html', data="whole foods cooking classes philadelphia")
@app.route('/whole-foods-cooking-classes-seattle')
def landing_usa_whole_foods_cooking17():
    return render_template('landing_usa.html', data="whole foods cooking classes seattle")
@app.route('/whole-foods-cooking-classes-minneapolis')
def landing_usa_whole_foods_cooking18():
    return render_template('landing_usa.html', data="whole foods cooking classes minneapolis")
@app.route('/whole-foods-cooking-classes-austin')
def landing_usa_whole_foods_cooking19():
    return render_template('landing_usa.html', data="whole foods cooking classes austin")

@app.route('/whole-foods-cooking-classes-in-dallas-tx')
def landing_usa_whole_foods_cooking20():
    return render_template('landing_usa.html', data="whole foods cooking classes in dallas tx")
@app.route('/whole-foods-cooking-classes-in-ri')
def landing_usa_whole_foods_cooking21():
    return render_template('landing_usa.html', data="whole foods cooking classes in ri")
@app.route('/whole-foods-cooking-classes-in-san-antonio-tx')
def landing_usa_whole_foods_cooking22():
    return render_template('landing_usa.html', data="whole foods cooking classes in san antonio tx")
@app.route('/whole-foods-cooking-classes-new-orleans')
def landing_usa_whole_foods_cooking23():
    return render_template('landing_usa.html', data="whole foods cooking classes new orleans")
@app.route('/whole-foods-cooking-classes-nashville-tn')
def landing_usa_whole_foods_cooking24():
    return render_template('landing_usa.html', data="whole foods cooking classes nashville tn")
@app.route('/whole-foods-cooking-classes-boston')
def landing_usa_whole_foods_cooking25():
    return render_template('landing_usa.html', data="whole foods cooking classes boston")
@app.route('/whole-foods-cooking-classes-denver')
def landing_usa_whole_foods_cooking26():
    return render_template('landing_usa.html', data="whole foods cooking classes denver")
@app.route('/whole-foods-cooking-classes-brooklyn')
def landing_usa_whole_foods_cooking27():
    return render_template('landing_usa.html', data="whole foods cooking classes brooklyn")
@app.route('/whole-foods-cooking-classes-miami')
def landing_usa_whole_foods_cooking28():
    return render_template('landing_usa.html', data="whole foods cooking classes miami")
@app.route('/whole-foods-cooking-classes-houston')
def landing_usa_whole_foods_cooking29():
    return render_template('landing_usa.html', data="whole foods cooking classes houston")

@app.route('/whole-foods-cooking-classes-bronx')
def landing_usa_whole_foods_cooking30():
    return render_template('landing_usa.html', data="whole foods cooking classes bronx")
@app.route('/whole-foods-cooking-classes-birmingham-al')
def landing_usa_whole_foods_cooking31():
    return render_template('landing_usa.html', data="whole foods cooking classes birmingham al")
@app.route('/whole-foods-cooking-classes-san-francisco')
def landing_usa_whole_foods_cooking32():
    return render_template('landing_usa.html', data="whole foods cooking classes san francisco")
@app.route('/whole-foods-cooking-classes-in-atlanta-ga')
def landing_usa_whole_foods_cooking33():
    return render_template('landing_usa.html', data="whole foods cooking classes in atlanta ga")
@app.route('/whole-foods-cooking-classes-phoenix-az')
def landing_usa_whole_foods_cooking34():
    return render_template('landing_usa.html', data="whole foods cooking classes phoenix az")
@app.route('/whole-foods-cooking-classes-richmond-va')
def landing_usa_whole_foods_cooking35():
    return render_template('landing_usa.html', data="whole foods cooking classes richmond va")
@app.route('/whole-foods-cooking-classes-mn')
def landing_usa_whole_foods_cooking36():
    return render_template('landing_usa.html', data="whole foods cooking classes mn")
@app.route('/whole-foods-cooking-classes-san-antonio-tx')
def landing_usa_whole_foods_cooking37():
    return render_template('landing_usa.html', data="whole foods cooking classes san antonio tx")
@app.route('/whole-foods-cooking-classes-sacramento')
def landing_usa_whole_foods_cooking38():
    return render_template('landing_usa.html', data="whole foods cooking classes sacramento")
@app.route('/whole-foods-cooking-classes-austin-tx')
def landing_usa_whole_foods_cooking39():
    return render_template('landing_usa.html', data="whole foods cooking classes austin tx")

@app.route('/whole-foods-cooking-classes-rochester-ny')
def landing_usa_whole_foods_cooking40():
    return render_template('landing_usa.html', data="whole foods cooking classes rochester ny")
@app.route('/whole-foods-cooking-classes-in-charlotte-nc')
def landing_usa_whole_foods_cooking41():
    return render_template('landing_usa.html', data="whole foods cooking classes in charlotte nc")
@app.route('/whole-foods-cooking-classes-tucson')
def landing_usa_whole_foods_cooking42():
    return render_template('landing_usa.html', data="whole foods cooking classes tucson")
@app.route('/whole-foods-cooking-classes-pittsburgh')
def landing_usa_whole_foods_cooking43():
    return render_template('landing_usa.html', data="whole foods cooking classes pittsburgh")
@app.route('/whole-foods-cooking-classes-in-detroit')
def landing_usa_whole_foods_cooking44():
    return render_template('landing_usa.html', data="whole foods cooking classes in detroit")
@app.route('/whole-foods-cooking-classes-kansas-city')
def landing_usa_whole_foods_cooking45():
    return render_template('landing_usa.html', data="whole foods cooking classes kansas city")
@app.route('/whole-foods-cooking-classes-detroit')
def landing_usa_whole_foods_cooking46():
    return render_template('landing_usa.html', data="whole foods cooking classes detroit")
@app.route('/whole-foods-cooking-classes-on-the-internet')
def landing_usa_whole_foods_cooking47():
    return render_template('landing_usa.html', data=" ")
@app.route('/teach-english-abroad-without-tefl-or-degree')
def landing_usa_whole_foods_cooking48():
    return render_template('landing_usa.html', data="whole foods cooking classes on the internet")
@app.route('/whole-foods-cooking-classes-mesa-az')
def landing_usa_whole_foods_cooking49():
    return render_template('landing_usa.html', data="whole foods cooking classes mesa az")

@app.route('/whole-foods-cooking-classes-greenville-sc')
def landing_usa_whole_foods_cooking50():
    return render_template('landing_usa.html', data="whole foods cooking classes greenville sc")
@app.route('/whole-foods-cooking-classes-washington-dc')
def landing_usa_whole_foods_cooking51():
    return render_template('landing_usa.html', data="whole foods cooking classes washington dc")
@app.route('/whole-foods-cooking-classes-louisville-ky')
def landing_usa_whole_foods_cooking52():
    return render_template('landing_usa.html', data="whole foods cooking classes louisville ky")
@app.route('/whole-foods-cooking-classes-in-knoxville-tn')
def landing_usa_whole_foods_cooking53():
    return render_template('landing_usa.html', data="whole foods cooking classes in knoxville tn")
@app.route('/whole-foods-cooking-classes-colorado-springs')
def landing_usa_whole_foods_cooking54():
    return render_template('landing_usa.html', data="whole foods cooking classes colorado springs")
@app.route('/whole-foods-cooking-classes-memphis-tn')
def landing_usa_whole_foods_cooking55():
    return render_template('landing_usa.html', data="whole foods cooking classes memphis tn")
@app.route('/whole-foods-cooking-classes-phoenix')
def landing_usa_whole_foods_cooking56():
    return render_template('landing_usa.html', data="whole foods cooking classes phoenix")
@app.route('/whole-foods-cooking-classes-boston-ma')
def landing_usa_whole_foods_cooking57():
    return render_template('landing_usa.html', data="whole foods cooking classes boston ma")
@app.route('/whole-foods-cooking-classes-st-louis-mo')
def landing_usa_whole_foods_cooking58():
    return render_template('landing_usa.html', data="whole foods cooking classes st louis mo")
@app.route('/whole-foods-cooking-classes-atlanta-ga')
def landing_usa_whole_foods_cooking59():
    return render_template('landing_usa.html', data="whole foods cooking classes atlanta ga")

@app.route('/whole-foods-cooking-classes-baton-rouge')
def landing_usa_whole_foods_cooking60():
    return render_template('landing_usa.html', data="whole foods cooking classes baton rouge")
@app.route('/whole-foods-cooking-classes-in-houston-texas')
def landing_usa_whole_foods_cooking61():
    return render_template('landing_usa.html', data="whole foods cooking classes in houston texas")
@app.route('/whole-foods-cooking-classes-san-antonio')
def landing_usa_whole_foods_cooking62():
    return render_template('landing_usa.html', data="whole foods cooking classes san antonio")
@app.route('/whole-foods-cooking-classes-houston-tx')
def landing_usa_whole_foods_cooking63():
    return render_template('landing_usa.html', data="whole foods cooking classes houston tx")
@app.route('/whole-foods-cooking-classes-dallas-tx')
def landing_usa_whole_foods_cooking64():
    return render_template('landing_usa.html', data=" ")
@app.route('/whole-foods-cooking-classes-portland-oregon')
def landing_usa_whole_foods_cooking65():
    return render_template('landing_usa.html', data="whole foods cooking classes portland oregon")
@app.route('/whole-foods-cooking-classes-queens-ny')
def landing_usa_whole_foods_cooking66():
    return render_template('landing_usa.html', data="whole foods cooking classes queens ny")
@app.route('/whole-foods-cooking-classes-cleveland-ohio')
def landing_usa_whole_foods_cooking67():
    return render_template('landing_usa.html', data="whole foods cooking classes cleveland ohio")
@app.route('/whole-foods-cooking-classes-bronx-ny')
def landing_usa_whole_foods_cooking68():
    return render_template('landing_usa.html', data="whole foods cooking classes bronx ny")
@app.route('/whole-foods-cooking-classes-tampa')
def landing_usa_whole_foods_cooking69():
    return render_template('landing_usa.html', data="whole foods cooking classes tampa")

@app.route('/whole-foods-cooking-classes-albany-ny')
def landing_usa_whole_foods_cooking70():
    return render_template('landing_usa.html', data="whole foods cooking classes albany ny")
@app.route('/whole-foods-cooking-classes-tampa-fl')
def landing_usa_whole_foods_cooking71():
    return render_template('landing_usa.html', data="whole foods cooking classes tampa fl")
@app.route('/whole-foods-cooking-classes-brooklyn-ny')
def landing_usa_whole_foods_cooking72():
    return render_template('landing_usa.html', data="whole foods cooking classes brooklyn ny")
@app.route('/whole-foods-cooking-classes-dc')
def landing_usa_whole_foods_cooking73():
    return render_template('landing_usa.html', data="whole foods cooking classes dc")
@app.route('/whole-foods-cooking-classes-knoxville-tne')
def landing_usa_whole_foods_cooking74():
    return render_template('landing_usa.html', data="whole foods cooking classes knoxville tn")
@app.route('/whole-foods-cooking-classes-raleigh-nc')
def landing_usa_whole_foods_cooking75():
    return render_template('landing_usa.html', data="whole foods cooking classes raleigh nc")
@app.route('/whole-foods-cooking-classes-staten-island-ny')
def landing_usa_whole_foods_cooking76():
    return render_template('landing_usa.html', data="whole foods cooking classes staten island ny")
@app.route('/whole-foods-cooking-classes-anchorage-ak')
def landing_usa_whole_foods_cooking77():
    return render_template('landing_usa.html', data="whole foods cooking classes anchorage ak")
@app.route('/whole-foods-cooking-classes-courses')
def landing_usa_whole_foods_cooking78():
    return render_template('landing_usa.html', data="whole foods cooking classes courses")
@app.route('/whole-foods-cooking-classes-sacramento-ca')
def landing_usa_whole_foods_cooking79():
    return render_template('landing_usa.html', data="whole foods cooking classes sacramento ca")

@app.route('/whole-foods-cooking-classes-chicago-il')
def landing_usa_whole_foods_cooking80():
    return render_template('landing_usa.html', data="whole foods cooking classes chicago il")
@app.route('/whole-foods-cooking-classes-miami-fl')
def landing_usa_whole_foods_cooking81():
    return render_template('landing_usa.html', data="whole foods cooking classes miami fl")
@app.route('/whole-foods-cooking-classes-bakersfield-ca')
def landing_usa_whole_foods_cooking82():
    return render_template('landing_usa.html', data="whole foods cooking classes bakersfield ca")
@app.route('/whole-foods-cooking-classes-baltimore-md')
def landing_usa_whole_foods_cooking83():
    return render_template('landing_usa.html', data="whole foods cooking classes baltimore md")
@app.route('/whole-foods-cooking-classes-new-york')
def landing_usa_whole_foods_cooking84():
    return render_template('landing_usa.html', data="whole foods cooking classes new york")
@app.route('/whole-foods-cooking-classes-las-vegas-nv')
def landing_usa_whole_foods_cooking85():
    return render_template('landing_usa.html', data="whole foods cooking classes las vegas nv")
@app.route('/whole-foods-cooking-classes-san-diego-ca')
def landing_usa_whole_foods_cooking86():
    return render_template('landing_usa.html', data="whole foods cooking classes san diego ca")
@app.route('/whole-foods-cooking-classes-austin-texas')
def landing_usa_whole_foods_cooking87():
    return render_template('landing_usa.html', data="whole foods cooking classes austin texas")
@app.route('/whole-foods-cooking-classes-milwaukee')
def landing_usa_whole_foods_cooking88():
    return render_template('landing_usa.html', data="whole foods cooking classes milwaukee")
@app.route('/whole-foods-cooking-classes-reno-nv')
def landing_usa_whole_foods_cooking89():
    return render_template('landing_usa.html', data="whole foods cooking classes reno nv")

@app.route('/whole-foods-cooking-classes-oklahoma-city')
def landing_usa_whole_foods_cooking90():
    return render_template('landing_usa.html', data="whole foods cooking classes oklahoma city")
@app.route('/whole-foods-cooking-classes-erie-pa')
def landing_usa_whole_foods_cooking91():
    return render_template('landing_usa.html', data="whole foods cooking classes erie pa")
@app.route('/whole-foods-cooking-classes-for-adults-in-chicago')
def landing_usa_whole_foods_cooking92():
    return render_template('landing_usa.html', data="whole foods cooking classes for adults in chicago")

####################################################################Italian Cooking Classes###############
@app.route('/italian-cooking-classes-nyc')
def landing_usa_italian_cooking1():
    return render_template('landing_usa.html', data="italian cooking classes nyc ")
@app.route('/italian-cooking-classes-near-me')
def landing_usa_italian_cooking2():
    return render_template('landing_usa.html', data="italian-cooking classes near me ")
@app.route('/italian-cooking-classes-in-chicago')
def landing_usa_italian_cooking3():
    return render_template('landing_usa.html', data="italian cooking classes in chicago ")
@app.route('/italian-cooking-classes-in-philadelphia')
def landing_usa_italian_cooking4():
    return render_template('landing_usa.html', data="italian cooking classes in philadelphia ")
@app.route('/italian-cooking-classes-in-houston')
def landing_usa_italian_cooking5():
    return render_template('landing_usa.html', data="italian cooking classes in houston")
@app.route('/italian-cooking-classes-in-dc')
def landing_usa_italian_cooking6():
    return render_template('landing_usa.html', data="italian cooking classes in dc")
@app.route('/italian-cooking-classes-for-adults-in-nyc')
def landing_usa_italian_cooking7():
    return render_template('landing_usa.html', data="italian cooking classes for adults in nyc")
@app.route('/italian-cooking-classes-san-diego')
def landing_usa_italian_cooking8():
    return render_template('landing_usa.html', data="italian cooking classes san diego")
@app.route('/italian-cooking-classes-nj')
def landing_usa_italian_cooking9():
    return render_template('landing_usa.html', data="italian cooking classes nj")

@app.route('/italian-cooking-classes-in-las-vegas')
def landing_usa_italian_cooking10():
    return render_template('landing_usa.html', data="italian cooking classes in las vegas")
@app.route('/italian-cooking-classes-in-nyc')
def landing_usa_italian_cooking11():
    return render_template('landing_usa.html', data="italian cooking classes in nyc")
@app.route('/italian-cooking-classes-buffalo-ny')
def landing_usa_italian_cooking12():
    return render_template('landing_usa.html', data="italian cooking classes buffalo ny")
@app.route('/italian-cooking-classes-los-angeles')
def landing_usa_italian_cooking13():
    return render_template('landing_usa.html', data="italian cooking classes los angeles")
@app.route('/italian-cooking-classes-in-columbus-ohio')
def landing_usa_italian_cooking14():
    return render_template('landing_usa.html', data="italian cooking classes in columbus ohio")
@app.route('/italian-cooking-classes-charlotte-nc')
def landing_usa_italian_cooking15():
    return render_template('landing_usa.html', data="italian cooking classes charlotte nc")
@app.route('/italian-cooking-classes-philadelphia')
def landing_usa_italian_cooking16():
    return render_template('landing_usa.html', data="italian cooking classes philadelphia")
@app.route('/italian-cooking-classes-seattle')
def landing_usa_italian_cooking17():
    return render_template('landing_usa.html', data="italian cooking classes seattle")
@app.route('/italian-cooking-classes-minneapolis')
def landing_usa_italian_cooking18():
    return render_template('landing_usa.html', data="italian cooking classes minneapolis")
@app.route('/italian-cooking-classes-austin')
def landing_usa_italian_cooking19():
    return render_template('landing_usa.html', data="italian cooking classes austin")

@app.route('/italian-cooking-classes-in-dallas-tx')
def landing_usa_italian_cooking20():
    return render_template('landing_usa.html', data="italian cooking classes in dallas tx")
@app.route('/italian-cooking-classes-in-ri')
def landing_usa_italian_cooking21():
    return render_template('landing_usa.html', data="italian cooking classes in ri")
@app.route('/italian-cooking-classes-in-san-antonio-tx')
def landing_usa_italian_cooking22():
    return render_template('landing_usa.html', data="italian cooking classes in san antonio tx")
@app.route('/italian-cooking-classes-new-orleans')
def landing_usa_italian_cooking23():
    return render_template('landing_usa.html', data="italian cooking classes new orleans")
@app.route('/italian-cooking-classes-nashville-tn')
def landing_usa_italian_cooking24():
    return render_template('landing_usa.html', data="italian cooking classes nashville tn")
@app.route('/italian-cooking-classes-boston')
def landing_usa_italian_cooking25():
    return render_template('landing_usa.html', data="italian cooking classes boston")
@app.route('/italian-cooking-classes-denver')
def landing_usa_italian_cooking26():
    return render_template('landing_usa.html', data="italian cooking classes denver")
@app.route('/italian-cooking-classes-brooklyn')
def landing_usa_italian_cooking27():
    return render_template('landing_usa.html', data="italian cooking classes brooklyn")
@app.route('/italian-cooking-classes-miami')
def landing_usa_italian_cooking28():
    return render_template('landing_usa.html', data="italian cooking classes miami")
@app.route('/italian-cooking-classes-houston')
def landing_usa_italian_cooking29():
    return render_template('landing_usa.html', data="italian cooking classes houston")

@app.route('/italian-cooking-classes-bronx')
def landing_usa_italian_cooking30():
    return render_template('landing_usa.html', data="italian cooking classes bronx")
@app.route('/italian-cooking-classes-birmingham-al')
def landing_usa_italian_cooking31():
    return render_template('landing_usa.html', data="italian cooking classes birmingham al")
@app.route('/italian-cooking-classes-san-francisco')
def landing_usa_italian_cooking32():
    return render_template('landing_usa.html', data="italian cooking classes san francisco")
@app.route('/italian-cooking-classes-in-atlanta-ga')
def landing_usa_italian_cooking33():
    return render_template('landing_usa.html', data="italian cooking classes in atlanta ga")
@app.route('/italian-cooking-classes-phoenix-az')
def landing_usa_italian_cooking34():
    return render_template('landing_usa.html', data="italian cooking classes phoenix az")
@app.route('/italian-cooking-classes-richmond-va')
def landing_usa_italian_cooking35():
    return render_template('landing_usa.html', data="italian cooking classes richmond va")
@app.route('/italian-cooking-classes-mn')
def landing_usa_italian_cooking36():
    return render_template('landing_usa.html', data="italian cooking classes mn")
@app.route('/italian-cooking-classes-san-antonio-tx')
def landing_usa_italian_cooking37():
    return render_template('landing_usa.html', data="italian cooking classes san antonio tx")
@app.route('/italian-cooking-classes-sacramento')
def landing_usa_italian_cooking38():
    return render_template('landing_usa.html', data="italian cooking classes sacramento")
@app.route('/italian-cooking-classes-austin-tx')
def landing_usa_italian_cooking39():
    return render_template('landing_usa.html', data="italian cooking classes austin tx")

@app.route('/italian-cooking-classes-rochester-ny')
def landing_usa_italian_cooking40():
    return render_template('landing_usa.html', data="italian cooking classes rochester ny")
@app.route('/italian-cooking-classes-in-charlotte-nc')
def landing_usa_italian_cooking41():
    return render_template('landing_usa.html', data="italian cooking classes in charlotte nc")
@app.route('/italian-cooking-classes-tucson')
def landing_usa_italian_cooking42():
    return render_template('landing_usa.html', data="italian cooking classes tucson")
@app.route('/italian-cooking-classes-pittsburgh')
def landing_usa_italian_cooking43():
    return render_template('landing_usa.html', data="italian cooking classes pittsburgh")
@app.route('/italian-cooking-classes-in-detroit')
def landing_usa_italian_cooking44():
    return render_template('landing_usa.html', data="italian cooking classes in detroit")
@app.route('/italian-cooking-classes-kansas-city')
def landing_usa_italian_cooking45():
    return render_template('landing_usa.html', data="italian cooking classes kansas city")
@app.route('/italian-cooking-classes-detroit')
def landing_usa_italian_cooking46():
    return render_template('landing_usa.html', data="italian cooking classes detroit")
@app.route('/italian-cooking-classes-on-the-internet')
def landing_usa_italian_cooking47():
    return render_template('landing_usa.html', data=" ")
@app.route('/teach-english-abroad-without-tefl-or-degree')
def landing_usa_italian_cooking48():
    return render_template('landing_usa.html', data="italian cooking classes on the internet")
@app.route('/italian-cooking-classes-mesa-az')
def landing_usa_italian_cooking49():
    return render_template('landing_usa.html', data="italian cooking classes mesa az")

@app.route('/italian-cooking-classes-greenville-sc')
def landing_usa_italian_cooking50():
    return render_template('landing_usa.html', data="italian cooking classes greenville sc")
@app.route('/italian-cooking-classes-washington-dc')
def landing_usa_italian_cooking51():
    return render_template('landing_usa.html', data="italian cooking classes washington dc")
@app.route('/italian-cooking-classes-louisville-ky')
def landing_usa_italian_cooking52():
    return render_template('landing_usa.html', data="italian cooking classes louisville ky")
@app.route('/italian-cooking-classes-in-knoxville-tn')
def landing_usa_italian_cooking53():
    return render_template('landing_usa.html', data="italian cooking classes in knoxville tn")
@app.route('/italian-cooking-classes-colorado-springs')
def landing_usa_italian_cooking54():
    return render_template('landing_usa.html', data="italian cooking classes colorado springs")
@app.route('/italian-cooking-classes-memphis-tn')
def landing_usa_italian_cooking55():
    return render_template('landing_usa.html', data="italian cooking classes memphis tn")
@app.route('/italian-cooking-classes-phoenix')
def landing_usa_italian_cooking56():
    return render_template('landing_usa.html', data="italian cooking classes phoenix")
@app.route('/italian-cooking-classes-boston-ma')
def landing_usa_italian_cooking57():
    return render_template('landing_usa.html', data="italian cooking classes boston ma")
@app.route('/italian-cooking-classes-st-louis-mo')
def landing_usa_italian_cooking58():
    return render_template('landing_usa.html', data="italian cooking classes st louis mo")
@app.route('/italian-cooking-classes-atlanta-ga')
def landing_usa_italian_cooking59():
    return render_template('landing_usa.html', data="italian cooking classes atlanta ga")

@app.route('/italian-cooking-classes-baton-rouge')
def landing_usa_italian_cooking60():
    return render_template('landing_usa.html', data="italian cooking classes baton rouge")
@app.route('/italian-cooking-classes-in-houston-texas')
def landing_usa_italian_cooking61():
    return render_template('landing_usa.html', data="italian cooking classes in houston texas")
@app.route('/italian-cooking-classes-san-antonio')
def landing_usa_italian_cooking62():
    return render_template('landing_usa.html', data="italian cooking classes san antonio")
@app.route('/italian-cooking-classes-houston-tx')
def landing_usa_italian_cooking63():
    return render_template('landing_usa.html', data="italian cooking classes houston tx")
@app.route('/italian-cooking-classes-dallas-tx')
def landing_usa_italian_cooking64():
    return render_template('landing_usa.html', data=" ")
@app.route('/italian-cooking-classes-portland-oregon')
def landing_usa_italian_cooking65():
    return render_template('landing_usa.html', data="italian cooking classes portland oregon")
@app.route('/italian-cooking-classes-queens-ny')
def landing_usa_italian_cooking66():
    return render_template('landing_usa.html', data="italian cooking classes queens ny")
@app.route('/italian-cooking-classes-cleveland-ohio')
def landing_usa_italian_cooking67():
    return render_template('landing_usa.html', data="italian cooking classes cleveland ohio")
@app.route('/italian-cooking-classes-bronx-ny')
def landing_usa_italian_cooking68():
    return render_template('landing_usa.html', data="italian cooking classes bronx ny")
@app.route('/italian-cooking-classes-tampa')
def landing_usa_italian_cooking69():
    return render_template('landing_usa.html', data="italian cooking classes tampa")

@app.route('/italian-cooking-classes-albany-ny')
def landing_usa_italian_cooking70():
    return render_template('landing_usa.html', data="italian cooking classes albany ny")
@app.route('/italian-cooking-classes-tampa-fl')
def landing_usa_italian_cooking71():
    return render_template('landing_usa.html', data="italian cooking classes tampa fl")
@app.route('/italian-cooking-classes-brooklyn-ny')
def landing_usa_italian_cooking72():
    return render_template('landing_usa.html', data="italian cooking classes brooklyn ny")
@app.route('/italian-cooking-classes-dc')
def landing_usa_italian_cooking73():
    return render_template('landing_usa.html', data="italian cooking classes dc")
@app.route('/italian-cooking-classes-knoxville-tne')
def landing_usa_italian_cooking74():
    return render_template('landing_usa.html', data="italian cooking classes knoxville tn")
@app.route('/italian-cooking-classes-raleigh-nc')
def landing_usa_italian_cooking75():
    return render_template('landing_usa.html', data="italian cooking classes raleigh nc")
@app.route('/italian-cooking-classes-staten-island-ny')
def landing_usa_italian_cooking76():
    return render_template('landing_usa.html', data="italian cooking classes staten island ny")
@app.route('/italian-cooking-classes-anchorage-ak')
def landing_usa_italian_cooking77():
    return render_template('landing_usa.html', data="italian cooking classes anchorage ak")
@app.route('/italian-cooking-classes-courses')
def landing_usa_italian_cooking78():
    return render_template('landing_usa.html', data="italian cooking classes courses")
@app.route('/italian-cooking-classes-sacramento-ca')
def landing_usa_italian_cooking79():
    return render_template('landing_usa.html', data="italian cooking classes sacramento ca")

@app.route('/italian-cooking-classes-chicago-il')
def landing_usa_italian_cooking80():
    return render_template('landing_usa.html', data="italian cooking classes chicago il")
@app.route('/italian-cooking-classes-miami-fl')
def landing_usa_italian_cooking81():
    return render_template('landing_usa.html', data="italian cooking classes miami fl")
@app.route('/italian-cooking-classes-bakersfield-ca')
def landing_usa_italian_cooking82():
    return render_template('landing_usa.html', data="italian cooking classes bakersfield ca")
@app.route('/italian-cooking-classes-baltimore-md')
def landing_usa_italian_cooking83():
    return render_template('landing_usa.html', data="italian cooking classes baltimore md")
@app.route('/italian-cooking-classes-new-york')
def landing_usa_italian_cooking84():
    return render_template('landing_usa.html', data="italian cooking classes new york")
@app.route('/italian-cooking-classes-las-vegas-nv')
def landing_usa_italian_cooking85():
    return render_template('landing_usa.html', data="italian cooking classes las vegas nv")
@app.route('/italian-cooking-classes-san-diego-ca')
def landing_usa_italian_cooking86():
    return render_template('landing_usa.html', data="italian cooking classes san diego ca")
@app.route('/italian-cooking-classes-austin-texas')
def landing_usa_italian_cooking87():
    return render_template('landing_usa.html', data="italian cooking classes austin texas")
@app.route('/italian-cooking-classes-milwaukee')
def landing_usa_italian_cooking88():
    return render_template('landing_usa.html', data="italian cooking classes milwaukee")
@app.route('/italian-cooking-classes-reno-nv')
def landing_usa_italian_cooking89():
    return render_template('landing_usa.html', data="italian cooking classes reno nv")

@app.route('/italian-cooking-classes-oklahoma-city')
def landing_usa_italian_cooking90():
    return render_template('landing_usa.html', data="italian cooking classes oklahoma city")
@app.route('/italian-cooking-classes-erie-pa')
def landing_usa_italian_cooking91():
    return render_template('landing_usa.html', data="italian cooking classes erie pa")
@app.route('/italian-cooking-classes-for-adults-in-chicago')
def landing_usa_italian_cooking92():
    return render_template('landing_usa.html', data="italian cooking classes for adults in chicago")