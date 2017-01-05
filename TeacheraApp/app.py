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
    try:
        message = Message(subject="Account created successfully!",
                            sender='support@teachera.eu',
                            reply_to='support@teachera.eu',
                           recipients=[current_user.email])
        body = "Hello:\t{0}\nYou have created an account on Teachera.org successfully."\
                        "\nYou can update your profile information here if you are a teacher or coach or tutor\n"\
                        "http://teachera.org/coach/activate/\n" \
                        "\n\n"\
                        "If you are looking to attend a class, update yours here"\
                        "http://teachera.org/profiles/create/\n" \
                        "\n\n"\
                        "Regards,\n"\
                        "Teachera.org team"  
        message.body= body.format(current_user.name)      
        mail.send(message)
    except:
        pass


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
@app.route('/list/Spain')
def sitemap__spain_html():
    return render_template('spain_sitemap.html')
@app.route('/list/uk')
def sitemap__uk_html():
    return render_template('uk_sitemap.html')

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
    try:
        applicant_details = db.session.query(Resume
                        ).filter_by(user_id=current_user.id).all()[0]
    except IndexError:
        return redirect(url_for('resume_create'))

    if applicant_details is None:
        return redirect(url_for('resume_create'))
    course = db.session.query(Course).get(course_id)
    if course is None:
        abort(404)
    elif current_user.id is None:
        abort(403)
    else:
        if current_user in course.users:
            flash("You have <strong>already applied</strong> for {0}.".format(course.course_title), 'warning')
        else:
            course.users.append(current_user)
            db.session.add(course)
            db.session.commit()
            flash("You have <strong>successfully applied</strong> for {0}.".format(course.course_title), 'success')
        return redirect(url_for('course_list'))
    try:
        message = Message(subject="Class signup successfully!",
                            sender='support@teachera.eu',
                            reply_to='support@teachera.eu',
                           recipients=[current_user.email])
        body = "Hello:\t{0}\nYou have signed up to a class successfully."\
                        "\nYou need to make an paymemt for this course. Contact the organizers or the teacher for more details\n"\
                        "\n\n"\
                        "Regards,\n"\
                        "Teachera.org team"  
        message.body= body.format(current_user.name)      
        mail.send(message)
    except:
        pass
        return redirect(url_for('course_list'))


@app.route('/courses/<int:course_id>/<course_title>/<city>')
def course_details(course_id , course_title , city):
    """Provide HTML page with all details on a given course.

    THIS VIEW IS FOR APPLICANTS
    """
    min_number = 4
    # Query: get Course object by ID.

    appt = db.session.query(Course).get(course_id)
    if current_user.is_anonymous:
        resume_exists = False
        anonymous = True
    else:
        resume_exists = bool(db.session.query(Resume).filter(Resume.user_id==current_user.id).count()> 0)
        anonymous = False
    return render_template('course/details.html', appt=appt,
                           have_resume=resume_exists, anonym=anonymous, min_number=min_number)
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
                            sender='info@teachera.eu',
                           reply_to='info@teachera.eu',
                           recipients=['info@teachera.eu'],
                           bcc=emails,
                           body=form.text.data)
            mail.send(message)
            flash("Message was sent.", 'success')
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
        appts = (db.session.query(CoachUserData).order_by(CoachUserData.id.asc()).all())
        
        return render_template('landing_teachers.html', appts=appts)

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
                        sender='info@teachera.eu',
                       reply_to=current_user.email,
                       recipients=['info@teachera.eu'],
                       body=form.text.data)
        mail.send(message)

        # Success. Send to the postion list
        flash("Your message was sent.", 'successful')
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
                       sender='info@teachera.eu',
                       reply_to=current_user.email,
                       recipients=[request.form['email']],
                       body=formated_text)
    mail.send(message)




    print request.__dict__
    print request.form
    return jsonify(status='success')


#######Views for certificate courses called "programs" ###



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

######################European Cities Begin #######

###############Yoga classes Keywords ##############

@app.route('/yoga-classes-in-Tirana')
def yoga_classes_one():
    return render_template('landing_europe.html', data='Yoga classes in Tirana')
@app.route('/yoga-classes-in-Andorra-la-Vella')
def yoga_classes_two():
    return render_template('landing_europe.html', data='Yoga classes in Andorra la Vella')
@app.route('/yoga-classes-in-Yerevan')
def yoga_classes_three():
    return render_template('landing_europe.html', data='Yoga classes in Yerevan')
@app.route('/yoga-classes-in-Vienna')
def yoga_classes_four():
    return render_template('landing_europe.html', data='Yoga classes in Vienna')
@app.route('/yoga-classes-in-Baku')
def yoga_classes_five():
    return render_template('landing_europe.html', data='Yoga classes in Baku')
@app.route('/yoga-classes-in-Minsk')
def yoga_classes_six():
    return render_template('landing_europe.html', data='Yoga classes in Minsk')
@app.route('/yoga-classes-in-Brussels')
def yoga_classes_seven():
    return render_template('landing_europe.html', data='Yoga classes in Brussels')
@app.route('/yoga-classes-in-Sarajevo')
def yoga_classes_eight():
    return render_template('landing_europe.html', data='Yoga classes in Sarajevo')

@app.route('/yoga-classes-in-Zagreb')
def yoga_classes_nine():
    return render_template('landing_europe.html', data='Yoga classes in Zagreb')
@app.route('/yoga-classes-in-Prague')
def yoga_classes_ten():
    return render_template('landing_europe.html', data='Yoga classes in Prague')
@app.route('/yoga-classes-in-Copenhagen')
def yoga_classes_eleven():
    return render_template('landing_europe.html', data='Yoga classes in Copenhagen')
@app.route('/yoga-classes-in-Tallinn')
def yoga_classes_twelve():
    return render_template('landing_europe.html', data='Yoga classes in Tallinn')
@app.route('/yoga-classes-in-Helsinki')
def yoga_classes_fourteen():
    return render_template('landing_europe.html', data='Yoga classes in Helsinki')
@app.route('/yoga-classes-in-Paris')
def yoga_classes_fifteen():
    return render_template('landing_europe.html', data='Yoga classes in Paris')
@app.route('/yoga-classes-in-Tbilisi')
def yoga_classes_sixteen():
    return render_template('landing_europe.html', data='Yoga classes in Tbilisi')
@app.route('/yoga-classes-in-Berlin')
def yoga_classes_seventeen():
    return render_template('landing_europe.html', data='Yoga classes in Berlin')
@app.route('/yoga-classes-in-Athens')
def yoga_classes_eighteen():
    return render_template('landing_europe.html', data='Yoga classes in Athens')
@app.route('/yoga-classes-in-Budapest')
def yoga_classes_nineteen():
    return render_template('landing_europe.html', data='Yoga classes in Budapest')
@app.route('/yoga-classes-in-Reykjavik')
def yoga_classes_twenty():
    return render_template('landing_europe.html', data='Yoga classes in Reykjavik')
@app.route('/yoga-classes-in-Dublin')
def yoga_classes_twenty_one():
    return render_template('landing_europe.html', data='Yoga classes in Dublin')
	
@app.route('/yoga-classes-in-Rome')
def yoga_classes_twenty_two():
    return render_template('landing_europe.html', data='Yoga classes in Rome')
@app.route('/yoga-classes-in-Pristina')
def yoga_classes_twenty_three():
    return render_template('landing_europe.html', data='Yoga classes in Pristina')
@app.route('/yoga-classes-in-Riga')
def yoga_classes_twenty_four():
    return render_template('landing_europe.html', data='Yoga classes in Riga')
@app.route('/yoga-classes-in-Vaduz')
def yoga_classes_twenty_five():
    return render_template('landing_europe.html', data='Yoga classes in Vaduz')
@app.route('/yoga-classes-in-Vilnius')
def yoga_classes_twenty_six():
    return render_template('landing_europe.html', data='Yoga classes in Vilnius')
@app.route('/yoga-classes-in-Luxembourg')
def yoga_classes_twenty_seven():
    return render_template('landing_europe.html', data='Yoga classes in Luxembourg')
@app.route('/yoga-classes-in-Skopje')
def yoga_classes_twenty_eight():
    return render_template('landing_europe.html', data='Yoga classes in Skopje')
@app.route('/yoga-classes-in-Chisinau')
def yoga_classes_twenty_nine():
    return render_template('landing_europe.html', data='Yoga classes in Chisinau')
@app.route('/yoga-classes-in-Podgorica')
def yoga_classes_thirty():
    return render_template('landing_europe.html', data='Yoga classes in Podgorica')
@app.route('/yoga-classes-in-Amsterdam')
def yoga_classes_thirty_one():
    return render_template('landing_europe.html', data='Yoga classes in Amsterdam')
@app.route('/yoga-classes-in-Oslo')
def yoga_classes_thirty_two():
    return render_template('landing_europe.html', data='Yoga classes in Oslo')
@app.route('/yoga-classes-in-Warsaw')
def yoga_classes_thirty_three():
    return render_template('landing_europe.html', data='Yoga classes in Warsaw')
@app.route('/yoga-classes-in-Lisbon')
def yoga_classes_thirty_four():
    return render_template('landing_europe.html', data='Yoga classes in Lisbon')
@app.route('/yoga-classes-in-Bucharest')
def yoga_classes_thirty_five():
    return render_template('landing_europe.html', data='Yoga classes in Bucharest')
@app.route('/yoga-classes-in-Moscow')
def yoga_classes_thirty_six():
    return render_template('landing_europe.html', data='Yoga classes in Moscow')
@app.route('/yoga-classes-in-San Marino')
def yoga_classes_thirty_seven():
    return render_template('landing_europe.html', data='Yoga classes in San Marino')
@app.route('/yoga-classes-in-Belgrade')
def yoga_classes_thirty_eight():
    return render_template('landing_europe.html', data='Yoga classes in Belgrade')
@app.route('/yoga-classes-in-Bratislava')
def yoga_classes_thirty_nine():
    return render_template('landing_europe.html', data='Yoga classes in Bratislava')
@app.route('/yoga-classes-in-Ljubljana')
def yoga_classes_fourty():
    return render_template('landing_europe.html', data='Yoga classes in Ljubljana')
@app.route('/yoga-classes-in-Madrid')
def yoga_classes_fourty_one():
    return render_template('landing_europe.html', data='Yoga classes in Madrid')
@app.route('/yoga-classes-in-Stockholm')
def yoga_classes_fourty_two():
    return render_template('landing_europe.html', data='Yoga classes in Stockholm')
@app.route('/yoga-classes-in-Bern')
def yoga_classes_fourty_three():
    return render_template('landing_europe.html', data='Yoga classes in Bern')
@app.route('/yoga-classes-in-Ankara')
def yoga_classes_fourty_four():
    return render_template('landing_europe.html', data='Yoga classes in Ankara')
@app.route('/yoga-classes-in-Kiev')
def yoga_classes_fourty_five():
    return render_template('landing_europe.html', data='Yoga classes in Kiev')
@app.route('/yoga-classes-in-London')
def yoga_classes_fourty_six():
    return render_template('landing_europe.html', data='Yoga classes in London')

###################Spanish_Keywords_Barcelona########
@app.route('/zumba clases en barcelona')
def barcelona_1():
    return render_template('landing_spanish.html', data='zumba clases en barcelona')
@app.route('/salsa clases en barcelona')
def barcelona_2():
    return render_template('landing_spanish.html', data='salsa clases en barcelona')
@app.route('/pole dance clases en barcelona')
def barcelona_3():
    return render_template('landing_spanish.html', data='pole dance clases en barcelona')
@app.route('/bollywood clases en barcelona')
def barcelona_4():
    return render_template('landing_spanish.html', data='bollywood clases en barcelona')
@app.route('/clases en barcelona')
def barcelona_5():
    return render_template('landing_spanish.html', data='krav-maga clases en barcelona')
@app.route('/flamenco clases en barcelona')
def barcelona_6():
    return render_template('landing_spanish.html', data='flamenco clases en barcelona')
@app.route('/clases de arabe en barcelona')
def barcelona_7():
    return render_template('landing_spanish.html', data='clases de arabe en barcelona')
@app.route('/clases de aikido en barcelona')
def barcelona_8():
    return render_template('landing_spanish.html', data='clases de aikido en barcelona')
@app.route('/clases de danza africana en barcelona')
def barcelona_9():
    return render_template('landing_spanish.html', data='clases de danza africana en barcelona')
@app.route('/clases de tiro con arco en barcelona')
def barcelona_10():
    return render_template('landing_spanish.html', data='clases de tiro con arco en barcelona')
@app.route('/clases de tango argentino en barcelona')
def barcelona_11():
    return render_template('landing_spanish.html', data='clases de tango argentino en barcelona')
@app.route('/clases de natacion para adultos en barcelona')
def barcelona_12():
    return render_template('landing_spanish.html', data='clases de natacion para adultos en barcelona')
@app.route('/clases de coser a maquina en barcelona')
def barcelona_13():
    return render_template('landing_spanish.html', data='clases de coser a maquina en barcelona')
@app.route('/clases de patinaje artistico en barcelona')
def barcelona_14():
    return render_template('landing_spanish.html', data='clases de patinaje artistico en barcelona')
@app.route('/clases particulares de ingles a domicilio en barcelona')
def barcelona_15():
    return render_template('landing_spanish.html', data='clases particulares de ingles a domicilio en barcelona')
@app.route('/clases de baile en barcelona')
def barcelona_16():
    return render_template('landing_spanish.html', data='clases de baile en barcelona')
@app.route('/clases de bachata en barcelona')
def barcelona_17():
    return render_template('landing_spanish.html', data='clases de bachata en barcelona')
@app.route('/clases de boxeo en barcelona')
def barcelona_18():
    return render_template('landing_spanish.html', data='clases de boxeo en barcelona')
@app.route('/clases de bateria en barcelona')
def barcelona_19():
    return render_template('landing_spanish.html', data='clases de bateria en barcelona')
@app.route('/clases de burlesque en barcelona')
def barcelona_20():
    return render_template('landing_spanish.html', data='clases de burlesque en barcelona')
@app.route('/clases de baile en barcelona gratis')
def barcelona_21():
    return render_template('landing_spanish.html', data='clases de baile en barcelona gratis')
@app.route('/clases de bridge en barcelona')
def barcelona_22():
    return render_template('landing_spanish.html', data='clases de bridge en barcelona')
@app.route('/clases de ballet en barcelona')
def barcelona_23():
    return render_template('landing_spanish.html', data='clases de ballet en barcelona')
@app.route('/clases de natacion para bebes en barcelona')
def barcelona_24():
    return render_template('landing_spanish.html', data='clases de natacion para bebes en barcelona')
@app.route('/clases de baile para ninos en barcelona')
def barcelona_25():
    return render_template('landing_spanish.html', data='clases de baile para ninos en barcelona')
@app.route('/clases de catalan en barcelona')
def barcelona_26():
    return render_template('landing_spanish.html', data='clases de catalan en barcelona')
@app.route('/clases de canto en barcelona')
def barcelona_27():
    return render_template('landing_spanish.html', data='clases de canto en barcelona')
@app.route('/clases de catalan gratis en barcelona')
def barcelona_28():
    return render_template('landing_spanish.html', data='clases de catalan gratis en barcelona')
@app.route('/clases de cocina en barcelona')
def barcelona_29():
    return render_template('landing_spanish.html', data='clases de cocina en barcelona')
@app.route('/clases de chino en barcelona')
def barcelona_30():
    return render_template('landing_spanish.html', data='clases de chino en barcelona')
@app.route('/clases de country en barcelona')
def barcelona_31():
    return render_template('landing_spanish.html', data='clases de country en barcelona')
@app.route('/clases de costura en barcelona')
def barcelona_32():
    return render_template('landing_spanish.html', data='clases de costura en barcelona')
@app.route('/gimnasios con clases de zumba en barcelona')
def barcelona_33():
    return render_template('landing_spanish.html', data='gimnasios con clases de zumba en barcelona')
@app.route('/clases de zumba en barcelona')
def barcelona_34():
    return render_template('landing_spanish.html', data='clases de zumba en barcelona')
@app.route('/clases de barcelona en barcelona')
def barcelona_35():
    return render_template('landing_spanish.html', data='clases de barcelona en barcelona')
@app.route('/clases particulares de ingles en barcelona')
def barcelona_36():
    return render_template('landing_spanish.html', data='clases particulares de ingles en barcelona')
@app.route('/clases de salsa en barcelona')
def barcelona_37():
    return render_template('landing_spanish.html', data='clases de salsa en barcelona')
@app.route('/clases de flamenco en barcelona')
def barcelona_38():
    return render_template('landing_spanish.html', data='clases de flamenco en barcelona')
@app.route('/clases de padel en barcelona')
def barcelona_39():
    return render_template('landing_spanish.html', data='clases de padel en barcelona')
@app.route('/clases de ruso en barcelona')
def barcelona_40():
    return render_template('landing_spanish.html', data='clases de ruso en barcelona')
@app.route('/clases de ingles en barcelona')
def barcelona_41():
    return render_template('landing_spanish.html', data='clases de ingles en barcelona')
@app.route('/clases de esgrima en barcelona')
def barcelona_42():
    return render_template('landing_spanish.html', data='clases de esgrima en barcelona')
@app.route('/en que idioma se dan las clases en la universidad de barcelona')
def barcelona_43():
    return render_template('landing_spanish.html', data='en que idioma se dan las clases en la universidad de barcelona')
@app.route('/clases de espanol en barcelona')
def barcelona_44():
    return render_template('landing_spanish.html', data='clases de espanol en barcelona')
@app.route('/clases de ronaldinho en el barcelona')
def barcelona_45():
    return render_template('landing_spanish.html', data='clases de ronaldinho en el barcelona')
@app.route('/clases de barcelona para embarazadas en barcelona')
def barcelona_46():
    return render_template('landing_spanish.html', data='clases de barcelona para embarazadas en barcelona')
@app.route('/clases de escalada en barcelona')
def barcelona_47():
    return render_template('landing_spanish.html', data='clases de escalada en barcelona')
@app.route('/clases de escultura en barcelona')
def barcelona_48():
    return render_template('landing_spanish.html', data='clases de escultura en barcelona')
@app.route('/clases de conversacion en ingles en barcelona')
def barcelona_49():
    return render_template('landing_spanish.html', data='clases de conversacion en ingles en barcelona')
@app.route('/clases de flamenco en barcelona gratis')
def barcelona_50():
    return render_template('landing_spanish.html', data='clases de flamenco en barcelona gratis')
@app.route('/clases de kung fu en barcelona')
def barcelona_51():
    return render_template('landing_spanish.html', data='clases de kung fu en barcelona')
@app.route('/clases de guitarra flamenca en barcelona')
def barcelona_52():
    return render_template('landing_spanish.html', data='clases de guitarra flamenca en barcelona')
@app.route('/clases de cajon flamenco en barcelona')
def barcelona_53():
    return render_template('landing_spanish.html', data='clases de cajon flamenco en barcelona')
@app.route('/clases de fotografia en barcelona')
def barcelona_54():
    return render_template('landing_spanish.html', data='clases de fotografia en barcelona')
@app.route('/clases de zumba fitness en barcelona')
def barcelona_55():
    return render_template('landing_spanish.html', data='clases de zumba fitness en barcelona')
@app.route('/clases de futbol para ninos en barcelona')
def barcelona_56():
    return render_template('landing_spanish.html', data='clases de futbol para ninos en barcelona')
@app.route('/clases de boxeo femenino en barcelona')
def barcelona_57():
    return render_template('landing_spanish.html', data='clases de boxeo femenino en barcelona')
@app.route('/clases particulares de fisica en barcelona')
def barcelona_58():
    return render_template('landing_spanish.html', data='clases particulares de fisica en barcelona')
@app.route('/clases de guitarra en barcelona')
def barcelona_59():
    return render_template('landing_spanish.html', data='clases de guitarra en barcelona')
@app.route('/clases de ingles gratis en barcelona')
def barcelona_60():
    return render_template('landing_spanish.html', data='clases de ingles gratis en barcelona')
@app.route('/clases de barcelona gratis en barcelona')
def barcelona_61():
    return render_template('landing_spanish.html', data='clases de barcelona gratis en barcelona')
@app.route('/clases de golf en barcelona')
def barcelona_62():
    return render_template('landing_spanish.html', data='clases de golf en barcelona')
@app.route('/clases de salsa en barcelona gratis')
def barcelona_63():
    return render_template('landing_spanish.html', data='clases de salsa en barcelona gratis')
@app.route('/clases de hipica en barcelona')
def barcelona_64():
    return render_template('landing_spanish.html', data='clases de hipica en barcelona')
@app.route('/clases de hebreo en barcelona')
def barcelona_65():
    return render_template('landing_spanish.html', data='clases de hebreo en barcelona')
@app.route('/clases de hebreo en barcelona')
def barcelona_66():
    return render_template('landing_spanish.html', data='clases de hebreo en barcelona')
@app.route('/clases de patinaje sobre hielo en barcelona')
def barcelona_67():
    return render_template('landing_spanish.html', data='clases de patinaje sobre hielo en barcelona')
@app.route('/clases de hip hop para ninos en barcelona')
def barcelona_68():
    return render_template('landing_spanish.html', data='clases de hip hop para ninos en barcelona')
@app.route('/clases de barcelona en horta barcelona')
def barcelona_69():
    return render_template('landing_spanish.html', data='clases de barcelona en horta barcelona')
@app.route('/clases de abdominales hipopresivos en barcelona')
def barcelona_70():
    return render_template('landing_spanish.html', data='clases de abdominales hipopresivos en barcelona')
@app.route('/donde hacer clases de zumba en barcelona')
def barcelona_71():
    return render_template('landing_spanish.html', data='donde hacer clases de zumba en barcelona')
@app.route('/clases de piano en horta barcelona')
def barcelona_72():
    return render_template('landing_spanish.html', data='clases de piano en horta barcelona')
@app.route('/clases de hapkido en barcelona')
def barcelona_73():
    return render_template('landing_spanish.html', data='clases de hapkido en barcelona')
@app.route('/clases de italiano en barcelona')
def barcelona_74():
    return render_template('landing_spanish.html', data='clases de italiano en barcelona')
@app.route('/clases particulares ingles en barcelona')
def barcelona_75():
    return render_template('landing_spanish.html', data='clases particulares ingles en barcelona')
@app.route('/clases de italiano gratis en barcelona')
def barcelona_76():
    return render_template('landing_spanish.html', data='clases de italiano gratis en barcelona')
@app.route('/clases particulares de ingles para ninos en barcelona')
def barcelona_77():
    return render_template('landing_spanish.html', data='clases particulares de ingles para ninos en barcelona')
@app.route('/clases particulares de informatica en barcelona')
def barcelona_78():
    return render_template('landing_spanish.html', data='clases particulares de informatica en barcelona')
@app.route('/clases de ingles para ninos en barcelona')
def barcelona_79():
    return render_template('landing_spanish.html', data='clases de ingles para ninos en barcelona')
@app.route('/clases de jazz en barcelona')
def barcelona_80():
    return render_template('landing_spanish.html', data='clases de jazz en barcelona')
@app.route('/clases particulares de japones en barcelona')
def barcelona_81():
    return render_template('landing_spanish.html', data='clases particulares de japones en barcelona')
@app.route('/clases de judo en barcelona')
def barcelona_82():
    return render_template('landing_spanish.html', data='clases de judo en barcelona')
@app.route('/clases de joyeria en barcelona')
def barcelona_83():
    return render_template('landing_spanish.html', data='clases de joyeria en barcelona')
@app.route('/clases de jiu jitsu en barcelona')
def barcelona_84():
    return render_template('landing_spanish.html', data='clases de jiu jitsu en barcelona')
@app.route('/clases de ragga jam en barcelona')
def barcelona_85():
    return render_template('landing_spanish.html', data='clases de ragga jam en barcelona')
@app.route('/clases de kangoo jumps en barcelona')
def barcelona_86():
    return render_template('landing_spanish.html', data='clases de kangoo jumps en barcelona')
@app.route('/clases de jeet kune do en barcelona')
def barcelona_87():
    return render_template('landing_spanish.html', data='clases de jeet kune do en barcelona')
@app.route('/clases de teatro para jovenes en barcelona')
def barcelona_88():
    return render_template('landing_spanish.html', data='clases de teatro para jovenes en barcelona')
@app.route('/clases de jumpstyle en barcelona')
def barcelona_89():
    return render_template('landing_spanish.html', data='clases de jumpstyle en barcelona')
@app.route('/clases de kizomba en barcelona')
def barcelona_90():
    return render_template('landing_spanish.html', data='clases de kizomba en barcelona')
@app.route('/clases de chi kung en barcelona')
def barcelona_91():
    return render_template('landing_spanish.html', data='clases de chi kung en barcelona')
@app.route('/clases de karate en barcelona')
def barcelona_92():
    return render_template('landing_spanish.html', data='clases de karate en barcelona')
@app.route('/clases de kitesurf en barcelona')
def barcelona_93():
    return render_template('landing_spanish.html', data='clases de kitesurf en barcelona')
@app.route('/clases de kendo en barcelona')
def barcelona_94():
    return render_template('landing_spanish.html', data='clases de kendo en barcelona')
@app.route('/clases de king boxing en barcelona')
def barcelona_95():
    return render_template('landing_spanish.html', data='clases de king boxing en barcelona')
@app.route('/krav maga en barcelona clases')
def barcelona_96():
    return render_template('landing_spanish.html', data='krav maga en barcelona clases')
@app.route('/clases de kayak en barcelona')
def barcelona_97():
    return render_template('landing_spanish.html', data='clases de kayak en barcelona')
@app.route('/clases de kundalini barcelona en barcelona')
def barcelona_98():
    return render_template('landing_spanish.html', data='clases de kundalini barcelona en barcelona')
@app.route('/clases de patinaje en linea barcelona')
def barcelona_99():
    return render_template('landing_spanish.html', data='clases de patinaje en linea barcelona')
@app.route('/clases de baile latino en barcelona')
def barcelona_100():
    return render_template('landing_spanish.html', data='clases de baile latino en barcelona')
@app.route('/clases de patinaje en linea gratis barcelona')
def barcelona_101():
    return render_template('landing_spanish.html', data='clases de patinaje en linea gratis barcelona')
@app.route('/clases de marinera en barcelona')
def barcelona_102():
    return render_template('landing_spanish.html', data='clases de marinera en barcelona')
@app.route('/clases de manualidades en barcelona')
def barcelona_103():
    return render_template('landing_spanish.html', data='clases de manualidades en barcelona')
@app.route('/clases de mma en barcelona')
def barcelona_104():
    return render_template('landing_spanish.html', data='clases de mma en barcelona')
@app.route('/clases particulares de matematicas en barcelona')
def barcelona_105():
    return render_template('landing_spanish.html', data='clases particulares de matematicas en barcelona')
@app.route('/clases de meditacion en barcelona')
def barcelona_106():
    return render_template('landing_spanish.html', data='clases de meditacion en barcelona')
@app.route('/clases de restauracion de muebles en barcelona')
def barcelona_107():
    return render_template('landing_spanish.html', data='clases de restauracion de muebles en barcelona')
@app.route('/clases de maquillaje en barcelona')
def barcelona_108():
    return render_template('landing_spanish.html', data='clases de maquillaje en barcelona')
@app.route('/clases de musica para bebes en barcelona')
def barcelona_109():
    return render_template('landing_spanish.html', data='clases de musica para bebes en barcelona')
@app.route('/clases de magia en barcelona')
def barcelona_110():
    return render_template('landing_spanish.html', data='clases de magia en barcelona')
@app.route('/clases de noruego en barcelona')
def barcelona_111():
    return render_template('landing_spanish.html', data='clases de noruego en barcelona')
@app.route('/clases de natacion en barcelona')
def barcelona_112():
    return render_template('landing_spanish.html', data='clases de natacion en barcelona')
@app.route('/clases de teatro para ninos en barcelona')
def barcelona_113():
    return render_template('landing_spanish.html', data='clases de teatro para ninos en barcelona')
@app.route('/clases de chino para ninos en barcelona')
def barcelona_114():
    return render_template('landing_spanish.html', data='clases de chino para ninos en barcelona')
@app.route('/clases de cocina para ninos en barcelona')
def barcelona_115():
    return render_template('landing_spanish.html', data='clases de cocina para ninos en barcelona')
@app.route('/clases de tenis para ninos en barcelona')
def barcelona_116():
    return render_template('landing_spanish.html', data='clases de tenis para ninos en barcelona')
@app.route('/clases de danza oriental en barcelona')
def barcelona_117():
    return render_template('landing_spanish.html', data='clases de danza oriental en barcelona')
@app.route('/clases de oratoria en barcelona')
def barcelona_118():
    return render_template('landing_spanish.html', data='clases de oratoria en barcelona')
@app.route('/ofertas de clases particulares en barcelona')
def barcelona_119():
    return render_template('landing_spanish.html', data='ofertas de clases particulares en barcelona')
@app.route('/clases de pintura al oleo en barcelona')
def barcelona_120():
    return render_template('landing_spanish.html', data='clases de pintura al oleo en barcelona')
@app.route('/oferta clases de padel en barcelona')
def barcelona_121():
    return render_template('landing_spanish.html', data='oferta clases de padel en barcelona')
@app.route('/oficina clases pasivas en barcelona')
def barcelona_122():
    return render_template('landing_spanish.html', data='oficina clases pasivas en barcelona')
@app.route('/clases de oboe en barcelona')
def barcelona_123():
    return render_template('landing_spanish.html', data='clases de oboe en barcelona')
@app.route('/clases de opera en barcelona')
def barcelona_124():
    return render_template('landing_spanish.html', data='clases de opera en barcelona')
@app.route('/clases de origami en barcelona')
def barcelona_125():
    return render_template('landing_spanish.html', data='clases de origami en barcelona')
@app.route('/clases particulares de quimica organica en barcelona')
def barcelona_126():
    return render_template('landing_spanish.html', data='clases particulares de quimica organica en barcelona')
@app.route('/clases de piano en barcelona')
def barcelona_127():
    return render_template('landing_spanish.html', data='clases de piano en barcelona')
@app.route('/clases particulares en barcelona')
def barcelona_128():
    return render_template('landing_spanish.html', data='clases particulares en barcelona')
@app.route('/clases de defensa personal en barcelona')
def barcelona_129():
    return render_template('landing_spanish.html', data='clases de defensa personal en barcelona')
@app.route('/clases de portugues en barcelona')
def barcelona_130():
    return render_template('landing_spanish.html', data='clases de portugues en barcelona')
@app.route('/clases de pintura en barcelona')
def barcelona_131():
    return render_template('landing_spanish.html', data='clases de pintura en barcelona')
@app.route('/dar clases particulares en barcelona')
def barcelona_132():
    return render_template('landing_spanish.html', data='dar clases particulares en barcelona')
@app.route('/clases particulares de quimica en barcelona')
def barcelona_133():
    return render_template('landing_spanish.html', data='clases particulares de quimica en barcelona')
@app.route('/clases de quechua en barcelona')
def barcelona_134():
    return render_template('landing_spanish.html', data='clases de quechua en barcelona')
@app.route('/que dia empiezan las clases en barcelona')
def barcelona_135():
    return render_template('landing_spanish.html', data='que dia empiezan las clases en barcelona')
@app.route('/que dia empiezan las clases en la universidad de barcelona')
def barcelona_136():
    return render_template('landing_spanish.html', data='que dia empiezan las clases en la universidad de barcelona')
@app.route('/en que idioma se imparten las clases en la universidad autonoma de barcelona')
def barcelona_137():
    return render_template('landing_spanish.html', data='en que idioma se imparten las clases en la universidad autonoma de barcelona')
@app.route('/clases preparto en quiron barcelona')
def barcelona_138():
    return render_template('landing_spanish.html', data='clases preparto en quiron barcelona')
@app.route('/clases particulares de ruso en barcelona')
def barcelona_139():
    return render_template('landing_spanish.html', data='clases particulares de ruso en barcelona')
@app.route('/clases de risoterapia en barcelona')
def barcelona_140():
    return render_template('landing_spanish.html', data='clases de risoterapia en barcelona')
@app.route('/clases de reposteria en barcelona')
def barcelona_141():
    return render_template('landing_spanish.html', data='clases de reposteria en barcelona')
@app.route('/clases de reggaeton en barcelona')
def barcelona_142():
    return render_template('landing_spanish.html', data='clases de reggaeton en barcelona')
@app.route('/clases de reiki en barcelona')
def barcelona_143():
    return render_template('landing_spanish.html', data='clases de reiki en barcelona')
@app.route('/clases de repaso en barcelona')
def barcelona_144():
    return render_template('landing_spanish.html', data='clases de repaso en barcelona')
@app.route('/clases de reiki gratis en barcelona')
def barcelona_145():
    return render_template('landing_spanish.html', data='clases de reiki gratis en barcelona')
@app.route('/clases de surf en barcelona')
def barcelona_146():
    return render_template('landing_spanish.html', data='clases de surf en barcelona')
@app.route('/clases de sevillanas en barcelona')
def barcelona_147():
    return render_template('landing_spanish.html', data='clases de sevillanas en barcelona')
@app.route('/clases particulares de salsa en barcelona')
def barcelona_148():
    return render_template('landing_spanish.html', data='clases particulares de salsa en barcelona')
@app.route('/clases de swing en barcelona')
def barcelona_149():
    return render_template('landing_spanish.html', data='clases de swing en barcelona')
@app.route('/clases de samba en barcelona')
def barcelona_150():
    return render_template('landing_spanish.html', data='clases de samba en barcelona')
@app.route('/clases de sueco en barcelona')
def barcelona_151():
    return render_template('landing_spanish.html', data='clases de sueco en barcelona')
@app.route('/clases de tango en barcelona')
def barcelona_152():
    return render_template('landing_spanish.html', data='clases de tango en barcelona')
@app.route('/clases de tenis en barcelona')
def barcelona_153():
    return render_template('landing_spanish.html', data='clases de tenis en barcelona')
@app.route('/clases de teatro en barcelona')
def barcelona_154():
    return render_template('landing_spanish.html', data='clases de teatro en barcelona')
@app.route('/clases de tai chi en barcelona')
def barcelona_155():
    return render_template('landing_spanish.html', data='clases de tai chi en barcelona')
@app.route('/clases de tango en barcelona gratis')
def barcelona_156():
    return render_template('landing_spanish.html', data='clases de tango en barcelona gratis')
@app.route('/clases de tenis para adultos en barcelona')
def barcelona_157():
    return render_template('landing_spanish.html', data='clases de tenis para adultos en barcelona')
@app.route('/clases de ukelele en barcelona')
def barcelona_158():
    return render_template('landing_spanish.html', data='clases de ukelele en barcelona')
@app.route('/clases de stand-up paddle en barcelona')
def barcelona_159():
    return render_template('landing_spanish.html', data='clases de stand-up paddle en barcelona')
@app.route('/universidad autonoma de barcelona clases en catalan')
def barcelona_160():
    return render_template('landing_spanish.html', data='universidad autonoma de barcelona clases en catalan')
@app.route('/en la universidad de barcelona se dan las clases en castellano')
def barcelona_161():
    return render_template('landing_spanish.html', data='en la universidad de barcelona se dan las clases en castellano')
@app.route('/clases de ingles en la universitat de barcelona')
def barcelona_162():
    return render_template('landing_spanish.html', data='clases de ingles en la universitat de barcelona')
@app.route('/clases de violin en barcelona')
def barcelona_163():
    return render_template('landing_spanish.html', data='clases de violin en barcelona')
@app.route('/danza del vientre en barcelona clases gratis')
def barcelona_164():
    return render_template('landing_spanish.html', data='danza del vientre en barcelona clases gratis')
@app.route('/clases de vela en barcelona')
def barcelona_165():
    return render_template('landing_spanish.html', data='clases de vela en barcelona')
@app.route('/clases danza del vientre en barcelona')
def barcelona_166():
    return render_template('landing_spanish.html', data='clases danza del vientre en barcelona')
@app.route('/clases de voleibol en barcelona')
def barcelona_167():
    return render_template('landing_spanish.html', data='clases de voleibol en barcelona')
@app.route('/clases de cocina vegetariana en barcelona')
def barcelona_168():
    return render_template('landing_spanish.html', data='clases de cocina vegetariana en barcelona')
@app.route('/clases de volleyball en barcelona')
def barcelona_169():
    return render_template('landing_spanish.html', data='clases de volleyball en barcelona')
@app.route('/clases de vietnamita en barcelona')
def barcelona_170():
    return render_template('landing_spanish.html', data='clases de vietnamita en barcelona')
@app.route('/clases de baile del vientre en barcelona')
def barcelona_171():
    return render_template('landing_spanish.html', data='clases de baile del vientre en barcelona')
@app.route('/clases de ingles en verano barcelona')
def barcelona_172():
    return render_template('landing_spanish.html', data='clases de ingles en verano barcelona')
@app.route('/clases de wing chun en barcelona')
def barcelona_173():
    return render_template('landing_spanish.html', data='clases de wing chun en barcelona')
@app.route('/clases de waterpolo en barcelona')
def barcelona_174():
    return render_template('landing_spanish.html', data='clases de waterpolo en barcelona')
@app.route('/windsurf en barcelona clases')
def barcelona_175():
    return render_template('landing_spanish.html', data='windsurf en barcelona clases')
@app.route('/clases de wakeboard en barcelona')
def barcelona_176():
    return render_template('landing_spanish.html', data='clases de wakeboard en barcelona')
@app.route('/clases particulares de wordpress en barcelona')
def barcelona_177():
    return render_template('landing_spanish.html', data='clases particulares de wordpress en barcelona')
@app.route('/clases de wordpress en barcelona')
def barcelona_178():
    return render_template('landing_spanish.html', data='clases de wordpress en barcelona')
@app.route('/clases de corte y confeccion en barcelona')
def barcelona_179():
    return render_template('landing_spanish.html', data='clases de corte y confeccion en barcelona')
@app.route('/clases de salsa y bachata en barcelona')
def barcelona_180():
    return render_template('landing_spanish.html', data='clases de salsa y bachata en barcelona')
@app.route('/clases de barcelona para ninos en barcelona')
def barcelona_181():
    return render_template('landing_spanish.html', data='clases de barcelona para ninos en barcelona')
@app.route('/clases de barcelona para ninos en barcelona')
def barcelona_182():
    return render_template('landing_spanish.html', data='clases de barcelona en gracia barcelona')
@app.route('/clases de barcelona en gracia barcelona')
def barcelona_183():
    return render_template('landing_spanish.html', data='clases de barcelona en barcelona centro')
@app.route('/clases de barcelona baratas en barcelona')
def barcelona_184():
    return render_template('landing_spanish.html', data='clases de barcelona baratas en barcelona')
@app.route('/clases de zouk en barcelona')
def barcelona_185():
    return render_template('landing_spanish.html', data='clases de zouk en barcelona')
@app.route('/clases de zumba en rubi barcelona')
def barcelona_186():
    return render_template('landing_spanish.html', data='clases de zumba en rubi barcelona')
@app.route('/donde dan clases de zumba en barcelona')
def barcelona_187():
    return render_template('landing_spanish.html', data='donde dan clases de zumba en barcelona')
@app.route('/clases de zumba en sant andreu barcelona')
def barcelona_188():
    return render_template('landing_spanish.html', data='clases de zumba en sant andreu barcelona')
@app.route('/clases de zumba en sarria barcelona')
def barcelona_189():
    return render_template('landing_spanish.html', data='clases de zumba en sarria barcelona')
@app.route('/clases de zumba en barcelona por la manana')
def barcelona_190():
    return render_template('landing_spanish.html', data='clases de zumba en barcelona por la manana')
@app.route('/clases de lambada zouk en barcelona')
def barcelona_191():
    return render_template('landing_spanish.html', data='clases de lambada zouk en barcelona')
@app.route('/clases de marinera en barcelona 2016')
def barcelona_192():
    return render_template('landing_spanish.html', data='clases de marinera en barcelona 2016')
##########################################################Spanish Keywords Madrid ################
@app.route('/zumba clases en madrid')
def madrid_1():
    return render_template('landing_spanish.html', data='zumba clases en madrid')
@app.route('/salsa clases en madrid')
def madrid_2():
    return render_template('landing_spanish.html', data='salsa clases en madrid')
@app.route('/pole dance clases en madrid')
def madrid_3():
    return render_template('landing_spanish.html', data='pole dance clases en madrid')
@app.route('/bollywood clases en madrid')
def madrid_4():
    return render_template('landing_spanish.html', data='bollywood clases en madrid')
@app.route('/clases en madrid')
def madrid_5():
    return render_template('landing_spanish.html', data='krav-maga clases en madrid')
@app.route('/flamenco clases en madrid')
def madrid_6():
    return render_template('landing_spanish.html', data='flamenco clases en madrid')
@app.route('/clases de arabe en madrid')
def madrid_7():
    return render_template('landing_spanish.html', data='clases de arabe en madrid')
@app.route('/clases de aikido en madrid')
def madrid_8():
    return render_template('landing_spanish.html', data='clases de aikido en madrid')
@app.route('/clases de danza africana en madrid')
def madrid_9():
    return render_template('landing_spanish.html', data='clases de danza africana en madrid')
@app.route('/clases de tiro con arco en madrid')
def madrid_10():
    return render_template('landing_spanish.html', data='clases de tiro con arco en madrid')
@app.route('/clases de tango argentino en madrid')
def madrid_11():
    return render_template('landing_spanish.html', data='clases de tango argentino en madrid')
@app.route('/clases de natacion para adultos en madrid')
def madrid_12():
    return render_template('landing_spanish.html', data='clases de natacion para adultos en madrid')
@app.route('/clases de coser a maquina en madrid')
def madrid_13():
    return render_template('landing_spanish.html', data='clases de coser a maquina en madrid')
@app.route('/clases de patinaje artistico en madrid')
def madrid_14():
    return render_template('landing_spanish.html', data='clases de patinaje artistico en madrid')
@app.route('/clases particulares de ingles a domicilio en madrid')
def madrid_15():
    return render_template('landing_spanish.html', data='clases particulares de ingles a domicilio en madrid')
@app.route('/clases de baile en madrid')
def madrid_16():
    return render_template('landing_spanish.html', data='clases de baile en madrid')
@app.route('/clases de bachata en madrid')
def madrid_17():
    return render_template('landing_spanish.html', data='clases de bachata en madrid')
@app.route('/clases de boxeo en madrid')
def madrid_18():
    return render_template('landing_spanish.html', data='clases de boxeo en madrid')
@app.route('/clases de bateria en madrid')
def madrid_19():
    return render_template('landing_spanish.html', data='clases de bateria en madrid')
@app.route('/clases de burlesque en madrid')
def madrid_20():
    return render_template('landing_spanish.html', data='clases de burlesque en madrid')
@app.route('/clases de baile en madrid gratis')
def madrid_21():
    return render_template('landing_spanish.html', data='clases de baile en madrid gratis')
@app.route('/clases de bridge en madrid')
def madrid_22():
    return render_template('landing_spanish.html', data='clases de bridge en madrid')
@app.route('/clases de ballet en madrid')
def madrid_23():
    return render_template('landing_spanish.html', data='clases de ballet en madrid')
@app.route('/clases de natacion para bebes en madrid')
def madrid_24():
    return render_template('landing_spanish.html', data='clases de natacion para bebes en madrid')
@app.route('/clases de baile para ninos en madrid')
def madrid_25():
    return render_template('landing_spanish.html', data='clases de baile para ninos en madrid')
@app.route('/clases de catalan en madrid')
def madrid_26():
    return render_template('landing_spanish.html', data='clases de catalan en madrid')
@app.route('/clases de canto en madrid')
def madrid_27():
    return render_template('landing_spanish.html', data='clases de canto en madrid')
@app.route('/clases de catalan gratis en madrid')
def madrid_28():
    return render_template('landing_spanish.html', data='clases de catalan gratis en madrid')
@app.route('/clases de cocina en madrid')
def madrid_29():
    return render_template('landing_spanish.html', data='clases de cocina en madrid')
@app.route('/clases de chino en madrid')
def madrid_30():
    return render_template('landing_spanish.html', data='clases de chino en madrid')
@app.route('/clases de country en madrid')
def madrid_31():
    return render_template('landing_spanish.html', data='clases de country en madrid')
@app.route('/clases de costura en madrid')
def madrid_32():
    return render_template('landing_spanish.html', data='clases de costura en madrid')
@app.route('/gimnasios con clases de zumba en madrid')
def madrid_33():
    return render_template('landing_spanish.html', data='gimnasios con clases de zumba en madrid')
@app.route('/clases de zumba en madrid')
def madrid_34():
    return render_template('landing_spanish.html', data='clases de zumba en madrid')
@app.route('/clases de madrid en madrid')
def madrid_35():
    return render_template('landing_spanish.html', data='clases de madrid en madrid')
@app.route('/clases particulares de ingles en madrid')
def madrid_36():
    return render_template('landing_spanish.html', data='clases particulares de ingles en madrid')
@app.route('/clases de salsa en madrid')
def madrid_37():
    return render_template('landing_spanish.html', data='clases de salsa en madrid')
@app.route('/clases de flamenco en madrid')
def madrid_38():
    return render_template('landing_spanish.html', data='clases de flamenco en madrid')
@app.route('/clases de padel en madrid')
def madrid_39():
    return render_template('landing_spanish.html', data='clases de padel en madrid')
@app.route('/clases de ruso en madrid')
def madrid_40():
    return render_template('landing_spanish.html', data='clases de ruso en madrid')
@app.route('/clases de ingles en madrid')
def madrid_41():
    return render_template('landing_spanish.html', data='clases de ingles en madrid')
@app.route('/clases de esgrima en madrid')
def madrid_42():
    return render_template('landing_spanish.html', data='clases de esgrima en madrid')
@app.route('/en que idioma se dan las clases en la universidad de madrid')
def madrid_43():
    return render_template('landing_spanish.html', data='en que idioma se dan las clases en la universidad de madrid')
@app.route('/clases de espanol en madrid')
def madrid_44():
    return render_template('landing_spanish.html', data='clases de espanol en madrid')
@app.route('/clases de ronaldinho en el madrid')
def madrid_45():
    return render_template('landing_spanish.html', data='clases de ronaldinho en el madrid')
@app.route('/clases de madrid para embarazadas en madrid')
def madrid_46():
    return render_template('landing_spanish.html', data='clases de madrid para embarazadas en madrid')
@app.route('/clases de escalada en madrid')
def madrid_47():
    return render_template('landing_spanish.html', data='clases de escalada en madrid')
@app.route('/clases de escultura en madrid')
def madrid_48():
    return render_template('landing_spanish.html', data='clases de escultura en madrid')
@app.route('/clases de conversacion en ingles en madrid')
def madrid_49():
    return render_template('landing_spanish.html', data='clases de conversacion en ingles en madrid')
@app.route('/clases de flamenco en madrid gratis')
def madrid_50():
    return render_template('landing_spanish.html', data='clases de flamenco en madrid gratis')
@app.route('/clases de kung fu en madrid')
def madrid_51():
    return render_template('landing_spanish.html', data='clases de kung fu en madrid')
@app.route('/clases de guitarra flamenca en madrid')
def madrid_52():
    return render_template('landing_spanish.html', data='clases de guitarra flamenca en madrid')
@app.route('/clases de cajon flamenco en madrid')
def madrid_53():
    return render_template('landing_spanish.html', data='clases de cajon flamenco en madrid')
@app.route('/clases de fotografia en madrid')
def madrid_54():
    return render_template('landing_spanish.html', data='clases de fotografia en madrid')
@app.route('/clases de zumba fitness en madrid')
def madrid_55():
    return render_template('landing_spanish.html', data='clases de zumba fitness en madrid')
@app.route('/clases de futbol para ninos en madrid')
def madrid_56():
    return render_template('landing_spanish.html', data='clases de futbol para ninos en madrid')
@app.route('/clases de boxeo femenino en madrid')
def madrid_57():
    return render_template('landing_spanish.html', data='clases de boxeo femenino en madrid')
@app.route('/clases particulares de fisica en madrid')
def madrid_58():
    return render_template('landing_spanish.html', data='clases particulares de fisica en madrid')
@app.route('/clases de guitarra en madrid')
def madrid_59():
    return render_template('landing_spanish.html', data='clases de guitarra en madrid')
@app.route('/clases de ingles gratis en madrid')
def madrid_60():
    return render_template('landing_spanish.html', data='clases de ingles gratis en madrid')
@app.route('/clases de madrid gratis en madrid')
def madrid_61():
    return render_template('landing_spanish.html', data='clases de madrid gratis en madrid')
@app.route('/clases de golf en madrid')
def madrid_62():
    return render_template('landing_spanish.html', data='clases de golf en madrid')
@app.route('/clases de salsa en madrid gratis')
def madrid_63():
    return render_template('landing_spanish.html', data='clases de salsa en madrid gratis')
@app.route('/clases de hipica en madrid')
def madrid_64():
    return render_template('landing_spanish.html', data='clases de hipica en madrid')
@app.route('/clases de hebreo en madrid')
def madrid_65():
    return render_template('landing_spanish.html', data='clases de hebreo en madrid')
@app.route('/clases de hebreo en madrid')
def madrid_66():
    return render_template('landing_spanish.html', data='clases de hebreo en madrid')
@app.route('/clases de patinaje sobre hielo en madrid')
def madrid_67():
    return render_template('landing_spanish.html', data='clases de patinaje sobre hielo en madrid')
@app.route('/clases de hip hop para ninos en madrid')
def madrid_68():
    return render_template('landing_spanish.html', data='clases de hip hop para ninos en madrid')
@app.route('/clases de madrid en horta madrid')
def madrid_69():
    return render_template('landing_spanish.html', data='clases de madrid en horta madrid')
@app.route('/clases de abdominales hipopresivos en madrid')
def madrid_70():
    return render_template('landing_spanish.html', data='clases de abdominales hipopresivos en madrid')
@app.route('/donde hacer clases de zumba en madrid')
def madrid_71():
    return render_template('landing_spanish.html', data='donde hacer clases de zumba en madrid')
@app.route('/clases de piano en horta madrid')
def madrid_72():
    return render_template('landing_spanish.html', data='clases de piano en horta madrid')
@app.route('/clases de hapkido en madrid')
def madrid_73():
    return render_template('landing_spanish.html', data='clases de hapkido en madrid')
@app.route('/clases de italiano en madrid')
def madrid_74():
    return render_template('landing_spanish.html', data='clases de italiano en madrid')
@app.route('/clases particulares ingles en madrid')
def madrid_75():
    return render_template('landing_spanish.html', data='clases particulares ingles en madrid')
@app.route('/clases de italiano gratis en madrid')
def madrid_76():
    return render_template('landing_spanish.html', data='clases de italiano gratis en madrid')
@app.route('/clases particulares de ingles para ninos en madrid')
def madrid_77():
    return render_template('landing_spanish.html', data='clases particulares de ingles para ninos en madrid')
@app.route('/clases particulares de informatica en madrid')
def madrid_78():
    return render_template('landing_spanish.html', data='clases particulares de informatica en madrid')
@app.route('/clases de ingles para ninos en madrid')
def madrid_79():
    return render_template('landing_spanish.html', data='clases de ingles para ninos en madrid')
@app.route('/clases de jazz en madrid')
def madrid_80():
    return render_template('landing_spanish.html', data='clases de jazz en madrid')
@app.route('/clases particulares de japones en madrid')
def madrid_81():
    return render_template('landing_spanish.html', data='clases particulares de japones en madrid')
@app.route('/clases de judo en madrid')
def madrid_82():
    return render_template('landing_spanish.html', data='clases de judo en madrid')
@app.route('/clases de joyeria en madrid')
def madrid_83():
    return render_template('landing_spanish.html', data='clases de joyeria en madrid')
@app.route('/clases de jiu jitsu en madrid')
def madrid_84():
    return render_template('landing_spanish.html', data='clases de jiu jitsu en madrid')
@app.route('/clases de ragga jam en madrid')
def madrid_85():
    return render_template('landing_spanish.html', data='clases de ragga jam en madrid')
@app.route('/clases de kangoo jumps en madrid')
def madrid_86():
    return render_template('landing_spanish.html', data='clases de kangoo jumps en madrid')
@app.route('/clases de jeet kune do en madrid')
def madrid_87():
    return render_template('landing_spanish.html', data='clases de jeet kune do en madrid')
@app.route('/clases de teatro para jovenes en madrid')
def madrid_88():
    return render_template('landing_spanish.html', data='clases de teatro para jovenes en madrid')
@app.route('/clases de jumpstyle en madrid')
def madrid_89():
    return render_template('landing_spanish.html', data='clases de jumpstyle en madrid')
@app.route('/clases de kizomba en madrid')
def madrid_90():
    return render_template('landing_spanish.html', data='clases de kizomba en madrid')
@app.route('/clases de chi kung en madrid')
def madrid_91():
    return render_template('landing_spanish.html', data='clases de chi kung en madrid')
@app.route('/clases de karate en madrid')
def madrid_92():
    return render_template('landing_spanish.html', data='clases de karate en madrid')
@app.route('/clases de kitesurf en madrid')
def madrid_93():
    return render_template('landing_spanish.html', data='clases de kitesurf en madrid')
@app.route('/clases de kendo en madrid')
def madrid_94():
    return render_template('landing_spanish.html', data='clases de kendo en madrid')
@app.route('/clases de king boxing en madrid')
def madrid_95():
    return render_template('landing_spanish.html', data='clases de king boxing en madrid')
@app.route('/krav maga en madrid clases')
def madrid_96():
    return render_template('landing_spanish.html', data='krav maga en madrid clases')
@app.route('/clases de kayak en madrid')
def madrid_97():
    return render_template('landing_spanish.html', data='clases de kayak en madrid')
@app.route('/clases de kundalini madrid en madrid')
def madrid_98():
    return render_template('landing_spanish.html', data='clases de kundalini madrid en madrid')
@app.route('/clases de patinaje en linea madrid')
def madrid_99():
    return render_template('landing_spanish.html', data='clases de patinaje en linea madrid')
@app.route('/clases de baile latino en madrid')
def madrid_100():
    return render_template('landing_spanish.html', data='clases de baile latino en madrid')
@app.route('/clases de patinaje en linea gratis madrid')
def madrid_101():
    return render_template('landing_spanish.html', data='clases de patinaje en linea gratis madrid')
@app.route('/clases de marinera en madrid')
def madrid_102():
    return render_template('landing_spanish.html', data='clases de marinera en madrid')
@app.route('/clases de manualidades en madrid')
def madrid_103():
    return render_template('landing_spanish.html', data='clases de manualidades en madrid')
@app.route('/clases de mma en madrid')
def madrid_104():
    return render_template('landing_spanish.html', data='clases de mma en madrid')
@app.route('/clases particulares de matematicas en madrid')
def madrid_105():
    return render_template('landing_spanish.html', data='clases particulares de matematicas en madrid')
@app.route('/clases de meditacion en madrid')
def madrid_106():
    return render_template('landing_spanish.html', data='clases de meditacion en madrid')
@app.route('/clases de restauracion de muebles en madrid')
def madrid_107():
    return render_template('landing_spanish.html', data='clases de restauracion de muebles en madrid')
@app.route('/clases de maquillaje en madrid')
def madrid_108():
    return render_template('landing_spanish.html', data='clases de maquillaje en madrid')
@app.route('/clases de musica para bebes en madrid')
def madrid_109():
    return render_template('landing_spanish.html', data='clases de musica para bebes en madrid')
@app.route('/clases de magia en madrid')
def madrid_110():
    return render_template('landing_spanish.html', data='clases de magia en madrid')
@app.route('/clases de noruego en madrid')
def madrid_111():
    return render_template('landing_spanish.html', data='clases de noruego en madrid')
@app.route('/clases de natacion en madrid')
def madrid_112():
    return render_template('landing_spanish.html', data='clases de natacion en madrid')
@app.route('/clases de teatro para ninos en madrid')
def madrid_113():
    return render_template('landing_spanish.html', data='clases de teatro para ninos en madrid')
@app.route('/clases de chino para ninos en madrid')
def madrid_114():
    return render_template('landing_spanish.html', data='clases de chino para ninos en madrid')
@app.route('/clases de cocina para ninos en madrid')
def madrid_115():
    return render_template('landing_spanish.html', data='clases de cocina para ninos en madrid')
@app.route('/clases de tenis para ninos en madrid')
def madrid_116():
    return render_template('landing_spanish.html', data='clases de tenis para ninos en madrid')
@app.route('/clases de danza oriental en madrid')
def madrid_117():
    return render_template('landing_spanish.html', data='clases de danza oriental en madrid')
@app.route('/clases de oratoria en madrid')
def madrid_118():
    return render_template('landing_spanish.html', data='clases de oratoria en madrid')
@app.route('/ofertas de clases particulares en madrid')
def madrid_119():
    return render_template('landing_spanish.html', data='ofertas de clases particulares en madrid')
@app.route('/clases de pintura al oleo en madrid')
def madrid_120():
    return render_template('landing_spanish.html', data='clases de pintura al oleo en madrid')
@app.route('/oferta clases de padel en madrid')
def madrid_121():
    return render_template('landing_spanish.html', data='oferta clases de padel en madrid')
@app.route('/oficina clases pasivas en madrid')
def madrid_122():
    return render_template('landing_spanish.html', data='oficina clases pasivas en madrid')
@app.route('/clases de oboe en madrid')
def madrid_123():
    return render_template('landing_spanish.html', data='clases de oboe en madrid')
@app.route('/clases de opera en madrid')
def madrid_124():
    return render_template('landing_spanish.html', data='clases de opera en madrid')
@app.route('/clases de origami en madrid')
def madrid_125():
    return render_template('landing_spanish.html', data='clases de origami en madrid')
@app.route('/clases particulares de quimica organica en madrid')
def madrid_126():
    return render_template('landing_spanish.html', data='clases particulares de quimica organica en madrid')
@app.route('/clases de piano en madrid')
def madrid_127():
    return render_template('landing_spanish.html', data='clases de piano en madrid')
@app.route('/clases particulares en madrid')
def madrid_128():
    return render_template('landing_spanish.html', data='clases particulares en madrid')
@app.route('/clases de defensa personal en madrid')
def madrid_129():
    return render_template('landing_spanish.html', data='clases de defensa personal en madrid')
@app.route('/clases de portugues en madrid')
def madrid_130():
    return render_template('landing_spanish.html', data='clases de portugues en madrid')
@app.route('/clases de pintura en madrid')
def madrid_131():
    return render_template('landing_spanish.html', data='clases de pintura en madrid')
@app.route('/dar clases particulares en madrid')
def madrid_132():
    return render_template('landing_spanish.html', data='dar clases particulares en madrid')
@app.route('/clases particulares de quimica en madrid')
def madrid_133():
    return render_template('landing_spanish.html', data='clases particulares de quimica en madrid')
@app.route('/clases de quechua en madrid')
def madrid_134():
    return render_template('landing_spanish.html', data='clases de quechua en madrid')
@app.route('/que dia empiezan las clases en madrid')
def madrid_135():
    return render_template('landing_spanish.html', data='que dia empiezan las clases en madrid')
@app.route('/que dia empiezan las clases en la universidad de madrid')
def madrid_136():
    return render_template('landing_spanish.html', data='que dia empiezan las clases en la universidad de madrid')
@app.route('/en que idioma se imparten las clases en la universidad autonoma de madrid')
def madrid_137():
    return render_template('landing_spanish.html', data='en que idioma se imparten las clases en la universidad autonoma de madrid')
@app.route('/clases preparto en quiron madrid')
def madrid_138():
    return render_template('landing_spanish.html', data='clases preparto en quiron madrid')
@app.route('/clases particulares de ruso en madrid')
def madrid_139():
    return render_template('landing_spanish.html', data='clases particulares de ruso en madrid')
@app.route('/clases de risoterapia en madrid')
def madrid_140():
    return render_template('landing_spanish.html', data='clases de risoterapia en madrid')
@app.route('/clases de reposteria en madrid')
def madrid_141():
    return render_template('landing_spanish.html', data='clases de reposteria en madrid')
@app.route('/clases de reggaeton en madrid')
def madrid_142():
    return render_template('landing_spanish.html', data='clases de reggaeton en madrid')
@app.route('/clases de reiki en madrid')
def madrid_143():
    return render_template('landing_spanish.html', data='clases de reiki en madrid')
@app.route('/clases de repaso en madrid')
def madrid_144():
    return render_template('landing_spanish.html', data='clases de repaso en madrid')
@app.route('/clases de reiki gratis en madrid')
def madrid_145():
    return render_template('landing_spanish.html', data='clases de reiki gratis en madrid')
@app.route('/clases de surf en madrid')
def madrid_146():
    return render_template('landing_spanish.html', data='clases de surf en madrid')
@app.route('/clases de sevillanas en madrid')
def madrid_147():
    return render_template('landing_spanish.html', data='clases de sevillanas en madrid')
@app.route('/clases particulares de salsa en madrid')
def madrid_148():
    return render_template('landing_spanish.html', data='clases particulares de salsa en madrid')
@app.route('/clases de swing en madrid')
def madrid_149():
    return render_template('landing_spanish.html', data='clases de swing en madrid')
@app.route('/clases de samba en madrid')
def madrid_150():
    return render_template('landing_spanish.html', data='clases de samba en madrid')
@app.route('/clases de sueco en madrid')
def madrid_151():
    return render_template('landing_spanish.html', data='clases de sueco en madrid')
@app.route('/clases de tango en madrid')
def madrid_152():
    return render_template('landing_spanish.html', data='clases de tango en madrid')
@app.route('/clases de tenis en madrid')
def madrid_153():
    return render_template('landing_spanish.html', data='clases de tenis en madrid')
@app.route('/clases de teatro en madrid')
def madrid_154():
    return render_template('landing_spanish.html', data='clases de teatro en madrid')
@app.route('/clases de tai chi en madrid')
def madrid_155():
    return render_template('landing_spanish.html', data='clases de tai chi en madrid')
@app.route('/clases de tango en madrid gratis')
def madrid_156():
    return render_template('landing_spanish.html', data='clases de tango en madrid gratis')
@app.route('/clases de tenis para adultos en madrid')
def madrid_157():
    return render_template('landing_spanish.html', data='clases de tenis para adultos en madrid')
@app.route('/clases de ukelele en madrid')
def madrid_158():
    return render_template('landing_spanish.html', data='clases de ukelele en madrid')
@app.route('/clases de stand-up paddle en madrid')
def madrid_159():
    return render_template('landing_spanish.html', data='clases de stand-up paddle en madrid')
@app.route('/universidad autonoma de madrid clases en catalan')
def madrid_160():
    return render_template('landing_spanish.html', data='universidad autonoma de madrid clases en catalan')
@app.route('/en la universidad de madrid se dan las clases en castellano')
def madrid_161():
    return render_template('landing_spanish.html', data='en la universidad de madrid se dan las clases en castellano')
@app.route('/clases de ingles en la universitat de madrid')
def madrid_162():
    return render_template('landing_spanish.html', data='clases de ingles en la universitat de madrid')
@app.route('/clases de violin en madrid')
def madrid_163():
    return render_template('landing_spanish.html', data='clases de violin en madrid')
@app.route('/danza del vientre en madrid clases gratis')
def madrid_164():
    return render_template('landing_spanish.html', data='danza del vientre en madrid clases gratis')
@app.route('/clases de vela en madrid')
def madrid_165():
    return render_template('landing_spanish.html', data='clases de vela en madrid')
@app.route('/clases danza del vientre en madrid')
def madrid_166():
    return render_template('landing_spanish.html', data='clases danza del vientre en madrid')
@app.route('/clases de voleibol en madrid')
def madrid_167():
    return render_template('landing_spanish.html', data='clases de voleibol en madrid')
@app.route('/clases de cocina vegetariana en madrid')
def madrid_168():
    return render_template('landing_spanish.html', data='clases de cocina vegetariana en madrid')
@app.route('/clases de volleyball en madrid')
def madrid_169():
    return render_template('landing_spanish.html', data='clases de volleyball en madrid')
@app.route('/clases de vietnamita en madrid')
def madrid_170():
    return render_template('landing_spanish.html', data='clases de vietnamita en madrid')
@app.route('/clases de baile del vientre en madrid')
def madrid_171():
    return render_template('landing_spanish.html', data='clases de baile del vientre en madrid')
@app.route('/clases de ingles en verano madrid')
def madrid_172():
    return render_template('landing_spanish.html', data='clases de ingles en verano madrid')
@app.route('/clases de wing chun en madrid')
def madrid_173():
    return render_template('landing_spanish.html', data='clases de wing chun en madrid')
@app.route('/clases de waterpolo en madrid')
def madrid_174():
    return render_template('landing_spanish.html', data='clases de waterpolo en madrid')
@app.route('/windsurf en madrid clases')
def madrid_175():
    return render_template('landing_spanish.html', data='windsurf en madrid clases')
@app.route('/clases de wakeboard en madrid')
def madrid_176():
    return render_template('landing_spanish.html', data='clases de wakeboard en madrid')
@app.route('/clases particulares de wordpress en madrid')
def madrid_177():
    return render_template('landing_spanish.html', data='clases particulares de wordpress en madrid')
@app.route('/clases de wordpress en madrid')
def madrid_178():
    return render_template('landing_spanish.html', data='clases de wordpress en madrid')
@app.route('/clases de corte y confeccion en madrid')
def madrid_179():
    return render_template('landing_spanish.html', data='clases de corte y confeccion en madrid')
@app.route('/clases de salsa y bachata en madrid')
def madrid_180():
    return render_template('landing_spanish.html', data='clases de salsa y bachata en madrid')
@app.route('/clases de madrid para ninos en madrid')
def madrid_181():
    return render_template('landing_spanish.html', data='clases de madrid para ninos en madrid')
@app.route('/clases de madrid para ninos en madrid')
def madrid_182():
    return render_template('landing_spanish.html', data='clases de madrid en gracia madrid')
@app.route('/clases de madrid en gracia madrid')
def madrid_183():
    return render_template('landing_spanish.html', data='clases de madrid en madrid centro')
@app.route('/clases de madrid baratas en madrid')
def madrid_184():
    return render_template('landing_spanish.html', data='clases de madrid baratas en madrid')
@app.route('/clases de zouk en madrid')
def madrid_185():
    return render_template('landing_spanish.html', data='clases de zouk en madrid')
@app.route('/clases de zumba en rubi madrid')
def madrid_186():
    return render_template('landing_spanish.html', data='clases de zumba en rubi madrid')
@app.route('/donde dan clases de zumba en madrid')
def madrid_187():
    return render_template('landing_spanish.html', data='donde dan clases de zumba en madrid')
@app.route('/clases de zumba en sant andreu madrid')
def madrid_188():
    return render_template('landing_spanish.html', data='clases de zumba en sant andreu madrid')
@app.route('/clases de zumba en sarria madrid')
def madrid_189():
    return render_template('landing_spanish.html', data='clases de zumba en sarria madrid')
@app.route('/clases de zumba en madrid por la manana')
def madrid_190():
    return render_template('landing_spanish.html', data='clases de zumba en madrid por la manana')
@app.route('/clases de lambada zouk en madrid')
def madrid_191():
    return render_template('landing_spanish.html', data='clases de lambada zouk en madrid')
@app.route('/clases de marinera en madrid 2016')
def madrid_192():
    return render_template('landing_spanish.html', data='clases de marinera en madrid 2016')

##############Londom Classes Keywords ################

@app.route('/dance-classes-london')
def london_1():
    return render_template('landing_europe.html', data="dance classes london")
@app.route('/cooking-classes-london')
def london_2():
    return render_template('landing_europe.html', data="cooking classes london")
@app.route('/pole-dancing-classes-london')
def london_3():
    return render_template('landing_europe.html', data="pole dancing classes london")
@app.route('/acting-classes-london')
def london_4():
    return render_template('landing_europe.html', data="acting classes london")
@app.route('/salsa-classes-london')
def london_5():
    return render_template('landing_europe.html', data="salsa classes london")
@app.route('/pottery-classes-london')
def london_6():
    return render_template('landing_europe.html', data="pottery classes london")
@app.route('/yoga-classes-london')
def london_7():
    return render_template('landing_europe.html', data="yoga classes london")
@app.route('/massage-courses-london')
def london_8():
    return render_template('landing_europe.html', data="massage courses london")
@app.route('/cocktail-making-classes-london')
def london_9():
    return render_template('landing_europe.html', data="cocktail making classes london")
@app.route('/life-drawing-classes-london')
def london_10():
    return render_template('landing_europe.html', data="life drawing classes london")
@app.route('/cookery-classes-london')
def london_11():
    return render_template('landing_europe.html', data="cookery classes london")
@app.route('/sewing-classes-london')
def london_12():
    return render_template('landing_europe.html', data="sewing classes london")
@app.route('/boxing-classes-london')
def london_13():
    return render_template('landing_europe.html', data="boxing classes london")
@app.route('/art-classes-london')
def london_14():
    return render_template('landing_europe.html', data="art classes london")
@app.route('/spanish-classes-london')
def london_15():
    return render_template('landing_europe.html', data="spanish classes london")
@app.route('/french-classes-london')
def london_16():
    return render_template('landing_europe.html', data="french classes london")
@app.route('/meditation-classes-london')
def london_17():
    return render_template('landing_europe.html', data="meditation classes london")
@app.route('/ballet-classes-london')
def london_18():
    return render_template('landing_europe.html', data="ballet classes london")
@app.route('/evening-classes-london')
def london_19():
    return render_template('landing_europe.html', data="evening classes london")
@app.route('/baking-classes-london')
def london_20():
    return render_template('landing_europe.html', data="baking classes london")
@app.route('/drawing-classes-london')
def london_21():
    return render_template('landing_europe.html', data="drawing classes london")
@app.route('/barre-classes-london')
def london_22():
    return render_template('landing_europe.html', data="barre classes london")
@app.route('/kickboxing-classes-london')
def london_23():
    return render_template('landing_europe.html', data="kickboxing classes london")
@app.route('/zumba-classes-london')
def london_24():
    return render_template('landing_europe.html', data="zumba classes london")
@app.route('/tango-classes-london')
def london_25():
    return render_template('landing_europe.html', data="tango classes london")
@app.route('/self-defence-classes-london')
def london_26():
    return render_template('landing_europe.html', data="self defence classes london")
@app.route('/spinning-classes-london')
def london_27():
    return render_template('landing_europe.html', data="spinning classes london")
@app.route('/pilates-classes-london')
def london_28():
    return render_template('landing_europe.html', data="pilates classes london")
@app.route('/contemporary-dance-classes-london')
def london_29():
    return render_template('landing_europe.html', data="contemporary dance classes london")
@app.route('/italian-classes-london')
def london_30():
    return render_template('landing_europe.html', data="italian classes london")
@app.route('/dance-classes-in-london')
def london_31():
    return render_template('landing_europe.html', data="dance classes in london")
@app.route('/painting-classes-london')
def london_32():
    return render_template('landing_europe.html', data="painting classes london")
@app.route('/fitness-classes-london')
def london_33():
    return render_template('landing_europe.html', data="fitness classes london")
@app.route('/cake-decorating-classes-london')
def london_34():
    return render_template('landing_europe.html', data="cake decorating classes london")
@app.route('/arabic-classes-london')
def london_35():
    return render_template('landing_europe.html', data="arabic classes london")
@app.route('/cooking-classes-in-london')
def london_36():
    return render_template('landing_europe.html', data="cooking classes in london")
@app.route('/improv-classes-london')
def london_37():
    return render_template('landing_europe.html', data="improv classes london")
@app.route('/belly-dancing-classes-london')
def london_38():
    return render_template('landing_europe.html', data="belly dancing classes london")
@app.route('/street-dance-classes-london')
def london_39():
    return render_template('landing_europe.html', data="street dance classes london")
@app.route('/german-classes-london')
def london_40():
    return render_template('landing_europe.html', data="german classes london")
@app.route('/bollywood-dance-classes-london')
def london_41():
    return render_template('landing_europe.html', data="bollywood dance classes london")
@app.route('/hip-hop-dance-classes-london')
def london_42():
    return render_template('landing_europe.html', data="hip hop dance classes london")
@app.route('/photography-classes-london')
def london_43():
    return render_template('landing_europe.html', data="photography classes london")
@app.route('/kizomba-classes-london')
def london_44():
    return render_template('landing_europe.html', data="kizomba classes london")
@app.route('/burlesque-classes-london')
def london_45():
    return render_template('landing_europe.html', data="burlesque classes london")
@app.route('/singing-classes-london')
def london_46():
    return render_template('landing_europe.html', data="singing classes london")
@app.route('/cooking-classes-london-ontario')
def london_47():
    return render_template('landing_europe.html', data="cooking classes london ontario")
@app.route('/chocolate-making-classes-london')
def london_48():
    return render_template('landing_europe.html', data="chocolate making classes london")
@app.route('/make-up-classes-london')
def london_49():
    return render_template('landing_europe.html', data="make up classes london")
@app.route('/free-yoga-classes-london')
def london_50():
    return render_template('landing_europe.html', data="free yoga classes london")
@app.route('/tai-chi-classes-london')
def london_51():
    return render_template('landing_europe.html', data="tai chi classes london")
@app.route('/sushi-classes-london')
def london_52():
    return render_template('landing_europe.html', data="sushi classes london")
@app.route('/yoga-classes-in-london')
def london_53():
    return render_template('landing_europe.html', data="yoga classes in london")
@app.route('/classes-in-london')
def london_54():
    return render_template('landing_europe.html', data="classes in london")
@app.route('/free-english-classes-london')
def london_55():
    return render_template('landing_europe.html', data="free english classes london")
@app.route('/drama-classes-london')
def london_56():
    return render_template('landing_europe.html', data="drama classes london")
@app.route('/insanity-classes-london')
def london_57():
    return render_template('landing_europe.html', data="insanity classes london")
@app.route('/indian-cooking-classes-london')
def london_58():
    return render_template('landing_europe.html', data="indian cooking classes london")
@app.route('/english-classes-in-london')
def london_59():
    return render_template('landing_europe.html', data="english classes in london")
@app.route('/ballroom-dance-classes-london')
def london_60():
    return render_template('landing_europe.html', data="ballroom dance classes london")
@app.route('/mma-classes-london')
def london_61():
    return render_template('landing_europe.html', data="mma classes london")
@app.route('/hula-hoop-classes-london')
def london_62():
    return render_template('landing_europe.html', data="hula hoop classes london")
@app.route('/flamenco-classes-london')
def london_63():
    return render_template('landing_europe.html', data="flamenco classes london")
@app.route('/free-dance-classes-london')
def london_64():
    return render_template('landing_europe.html', data="free dance classes london")
@app.route('/knitting-classes-london')
def london_65():
    return render_template('landing_europe.html', data="knitting classes london")
@app.route('/exercise-classes-london')
def london_66():
    return render_template('landing_europe.html', data="exercise classes london")
@app.route('/ielts-courses-in-london')
def london_67():
    return render_template('landing_europe.html', data="ielts courses in london")
@app.route('/fencing-classes-london')
def london_68():
    return render_template('landing_europe.html', data="fencing classes london")
@app.route('/japanese-classes-london')
def london_69():
    return render_template('landing_europe.html', data="japanese classes london")
@app.route('/english-classes-london')
def london_70():
    return render_template('landing_europe.html', data="english classes london")
@app.route('/latin-dance-classes-london')
def london_71():
    return render_template('landing_europe.html', data="latin dance classes london")
@app.route('/vegetarian-cooking-classes-london')
def london_72():
    return render_template('landing_europe.html', data="vegetarian cooking classes london")
@app.route('/free-acting-classes-london')
def london_73():
    return render_template('landing_europe.html', data="free acting classes london")
@app.route('/salsa-classes-in-london')
def london_74():
    return render_template('landing_europe.html', data="salsa classes in london")
@app.route('/bachata-classes-london')
def london_75():
    return render_template('landing_europe.html', data="bachata classes london")
@app.route('/acting-classes-in-london')
def london_76():
    return render_template('landing_europe.html', data="acting classes in london")
@app.route('/samba-classes-london')
def london_77():
    return render_template('landing_europe.html', data="samba classes london")
@app.route('/classes-london')
def london_78():
    return render_template('landing_europe.html', data="classes london")
@app.route('/language-classes-london')
def london_79():
    return render_template('landing_europe.html', data="language classes london")
@app.route('/african-dance-classes-london')
def london_80():
    return render_template('landing_europe.html', data="african dance classes london")
@app.route('/jamie-oliver-cooking-classes-london')
def london_81():
    return render_template('landing_europe.html', data="jamie oliver cooking classes london")
@app.route('/dancehall-classes-london')
def london_82():
    return render_template('landing_europe.html', data="dancehall classes london")
@app.route('/french-evening-classes-london')
def london_83():
    return render_template('landing_europe.html', data="french evening classes london")
@app.route('/craft-classes-london')
def london_84():
    return render_template('landing_europe.html', data="craft classes london")
@app.route('/cheap-yoga-classes-london')
def london_85():
    return render_template('landing_europe.html', data="cheap yoga classes london")
@app.route('/mandarin-classes-london')
def london_86():
    return render_template('landing_europe.html', data="mandarin classes london")
@app.route('/swing-dance-classes-london')
def london_87():
    return render_template('landing_europe.html', data="swing dance classes london")
@app.route('/vegan-cooking-classes-london')
def london_88():
    return render_template('landing_europe.html', data="vegan cooking classes london")
@app.route('/kettlebell-classes-london')
def london_89():
    return render_template('landing_europe.html', data="kettlebell classes london")
@app.route('/aquanatal-classes-london')
def london_90():
    return render_template('landing_europe.html', data="aquanatal classes london")
@app.route('/jive-classes-london')
def london_91():
    return render_template('landing_europe.html', data="jive classes london")
@app.route('/tennis-classes-london')
def london_92():
    return render_template('landing_europe.html', data="tennis classes london")
@app.route('/art-classes-london-ontario')
def london_93():
    return render_template('landing_europe.html', data="art classes london ontario")
@app.route('/art-classes-in-london')
def london_94():
    return render_template('landing_europe.html', data="art classes in london")
@app.route('/portuguese-classes-london')
def london_95():
    return render_template('landing_europe.html', data="portuguese classes london")
@app.route('/krav-maga-classes-london')
def london_96():
    return render_template('landing_europe.html', data="krav maga classes london")
@app.route('/italian-cooking-classes-london')
def london_97():
    return render_template('landing_europe.html', data="italian cooking classes london")
@app.route('/evening-cooking-classes-london')
def london_98():
    return render_template('landing_europe.html', data="evening cooking classes london")
@app.route('/antenatal-classes-london')
def london_99():
    return render_template('landing_europe.html', data="antenatal classes london")
@app.route('/wine-tasting-courses-london')
def london_100():
    return render_template('landing_europe.html', data="wine tasting courses london")
@app.route('/trx-classes-london')
def london_101():
    return render_template('landing_europe.html', data="trx classes london")
@app.route('/parkour-classes-london')
def london_102():
    return render_template('landing_europe.html', data="parkour classes london")
@app.route('/kung-fu-classes-london')
def london_103():
    return render_template('landing_europe.html', data="kung fu classes london")
@app.route('/pole-dancing-classes-london-ontario')
def london_104():
    return render_template('landing_europe.html', data="pole dancing classes london ontario")
@app.route('/gym-classes-london')
def london_105():
    return render_template('landing_europe.html', data="gym classes london")
@app.route('/french-classes-in-london')
def london_106():
    return render_template('landing_europe.html', data="french classes in london")
@app.route('/yoga-classes-london-ontario')
def london_107():
    return render_template('landing_europe.html', data="yoga classes london ontario")
@app.route('/gymnastics-classes-london')
def london_108():
    return render_template('landing_europe.html', data="gymnastics classes london")
@app.route('/spanish-classes-in-london')
def london_109():
    return render_template('landing_europe.html', data="spanish classes in london")
@app.route('/butchery-classes-london')
def london_110():
    return render_template('landing_europe.html', data="butchery classes london")
@app.route('/writing-classes-london')
def london_111():
    return render_template('landing_europe.html', data="writing classes london")
@app.route('/martial-arts-classes-london')
def london_112():
    return render_template('landing_europe.html', data="martial arts classes london")
@app.route('/prenatal-classes-london-ontario')
def london_113():
    return render_template('landing_europe.html', data="prenatal classes london ontario")
@app.route('/night-classes-london')
def london_114():
    return render_template('landing_europe.html', data="night classes london")
@app.route('/aerial-hoop-classes-london')
def london_115():
    return render_template('landing_europe.html', data="aerial hoop classes london")
@app.route('/oil-painting-classes-london')
def london_116():
    return render_template('landing_europe.html', data="oil painting classes london")
@app.route('/trampoline-classes-london')
def london_117():
    return render_template('landing_europe.html', data="trampoline classes london")
@app.route('/karate-classes-london')
def london_118():
    return render_template('landing_europe.html', data="karate classes london")
@app.route('/tap-classes-london')
def london_119():
    return render_template('landing_europe.html', data="tap classes london")
@app.route('/boxing-classes-in-london')
def london_120():
    return render_template('landing_europe.html', data="boxing classes in london")
@app.route('/wing-chun-classes-london')
def london_121():
    return render_template('landing_europe.html', data="wing chun classes london")
@app.route('/dressmaking-classes-london')
def london_122():
    return render_template('landing_europe.html', data="dressmaking classes london")
@app.route('/muay-thai-classes-london')
def london_123():
    return render_template('landing_europe.html', data="muay thai classes london")
@app.route('/hypnobirthing-classes-london')
def london_124():
    return render_template('landing_europe.html', data="hypnobirthing classes london")
@app.route('/healthy-cooking-classes-london')
def london_125():
    return render_template('landing_europe.html', data="healthy cooking classes london")
@app.route('/russian-classes-london')
def london_126():
    return render_template('landing_europe.html', data="russian classes london")
@app.route('/mixology-classes-london')
def london_127():
    return render_template('landing_europe.html', data="mixology classes london")
@app.route('/pottery-classes-in-london')
def london_128():
    return render_template('landing_europe.html', data="pottery classes in london")
@app.route('/zumba-classes-in-london')
def london_129():
    return render_template('landing_europe.html', data="zumba classes in london")
@app.route('/cupcake-classes-london')
def london_130():
    return render_template('landing_europe.html', data="cupcake classes london")
@app.route('/free-english-classes-in-london')
def london_131():
    return render_template('landing_europe.html', data="free english classes in london")
@app.route('/baking-classes-in-london')
def london_132():
    return render_template('landing_europe.html', data="baking classes in london")
@app.route('/evening-art-classes-london')
def london_133():
    return render_template('landing_europe.html', data="evening art classes london")
@app.route('/sewing-classes-in-london')
def london_134():
    return render_template('landing_europe.html', data="sewing classes in london")
@app.route('/ballet-classes-in-london')
def london_135():
    return render_template('landing_europe.html', data="ballet classes in london")
@app.route('/guitar-classes-london')
def london_136():
    return render_template('landing_europe.html', data="guitar classes london")
@app.route('/womens-boxing-classes-london')
def london_137():
    return render_template('landing_europe.html', data="women's boxing classes london")
@app.route('/kathak-classes-london')
def london_138():
    return render_template('landing_europe.html', data="kathak classes london")
@app.route('/evening-acting-classes-london')
def london_139():
    return render_template('landing_europe.html', data="evening acting classes london")
@app.route('/anger-management-courses-london')
def london_140():
    return render_template('landing_europe.html', data="anger management courses london")
@app.route('/trapeze-classes-london')
def london_141():
    return render_template('landing_europe.html', data="trapeze classes london")
@app.route('/lindy-hop-classes-london')
def london_142():
    return render_template('landing_europe.html', data="lindy hop classes london")
@app.route('/glass-blowing-classes-london')
def london_143():
    return render_template('landing_europe.html', data="glass blowing classes london")
@app.route('/woodwork-classes-london')
def london_144():
    return render_template('landing_europe.html', data="woodwork classes london")
@app.route('/pole-dancing-classes-in-london')
def london_145():
    return render_template('landing_europe.html', data="pole dancing classes in london")
@app.route('/upholstery-classes-london')
def london_146():
    return render_template('landing_europe.html', data="upholstery classes london")
@app.route('/tajweed-classes-london')
def london_147():
    return render_template('landing_europe.html', data="tajweed classes london")
@app.route('/thai-cooking-classes-london')
def london_148():
    return render_template('landing_europe.html', data="thai cooking classes london")
@app.route('/1-day-pottery-classes-london')
def london_149():
    return render_template('landing_europe.html', data="1 day pottery classes london")
@app.route('/qigong-classes-london')
def london_150():
    return render_template('landing_europe.html', data="qigong classes london")
@app.route('/judo-classes-london')
def london_151():
    return render_template('landing_europe.html', data="judo classes london")
@app.route('/embroidery-classes-london')
def london_152():
    return render_template('landing_europe.html', data="embroidery classes london")
@app.route('/drop-in-dance-classes-london')
def london_153():
    return render_template('landing_europe.html', data="drop in dance classes london")
@app.route('/pilates-classes-in-london')
def london_154():
    return render_template('landing_europe.html', data="pilates classes in london")
@app.route('/cookery-classes-in-london')
def london_155():
    return render_template('landing_europe.html', data="cookery classes in london")
@app.route('/kendo-classes-london')
def london_156():
    return render_template('landing_europe.html', data="kendo classes london")
@app.route('/jewellery-making-classes-london')
def london_157():
    return render_template('landing_europe.html', data="jewellery making classes london")
@app.route('/kizomba-classes-in-london')
def london_158():
    return render_template('landing_europe.html', data="kizomba classes in london")
@app.route('/etiquette-classes-london')
def london_159():
    return render_template('landing_europe.html', data="etiquette classes london")
@app.route('/fitness-classes-in-london')
def london_160():
    return render_template('landing_europe.html', data="fitness classes in london")
@app.route('/violin-classes-london')
def london_161():
    return render_template('landing_europe.html', data="violin classes london")
@app.route('/life-drawing-classes-london-free')
def london_162():
    return render_template('landing_europe.html', data="life drawing classes london free")
@app.route('/power-plate-classes-london')
def london_163():
    return render_template('landing_europe.html', data="power plate classes london")
@app.route('/quran-classes-london')
def london_164():
    return render_template('landing_europe.html', data="quran classes london")
@app.route('/yoga-classes-london-bridge')
def london_165():
    return render_template('landing_europe.html', data="yoga classes london bridge")
@app.route('/dog-training-classes-london')
def london_166():
    return render_template('landing_europe.html', data="dog training classes london")
@app.route('/hebrew-classes-london')
def london_167():
    return render_template('landing_europe.html', data="hebrew classes london")
@app.route('/islamic-classes-london')
def london_168():
    return render_template('landing_europe.html', data="islamic classes london")
@app.route('/wrestling-classes-london')
def london_169():
    return render_template('landing_europe.html', data="wrestling classes london")
@app.route('/hindi-classes-london')
def london_170():
    return render_template('landing_europe.html', data="hindi classes london")
@app.route('/kundalini-yoga-classes-london')
def london_171():
    return render_template('landing_europe.html', data="kundalini yoga classes london")
@app.route('/free-classes-in-london')
def london_172():
    return render_template('landing_europe.html', data="free classes in london")
@app.route('/elocution-classes-london')
def london_173():
    return render_template('landing_europe.html', data="elocution classes london")
@app.route('/cocktail-making-classes-in-london')
def london_174():
    return render_template('landing_europe.html', data="cocktail making classes in london")
@app.route('/indian-dance-classes-london')
def london_175():
    return render_template('landing_europe.html', data="indian dance classes london")
@app.route('/dj-classes-london')
def london_176():
    return render_template('landing_europe.html', data="dj classes london")
@app.route('/german-evening-classes-london')
def london_177():
    return render_template('landing_europe.html', data="german evening classes london")
@app.route('/italian-evening-classes-london')
def london_178():
    return render_template('landing_europe.html', data="italian evening classes london")
@app.route('/tap-dancing-classes-london')
def london_179():
    return render_template('landing_europe.html', data="tap dancing classes london")
@app.route('/french-conversation-classes-london')
def london_180():
    return render_template('landing_europe.html', data="french conversation classes london")
@app.route('/hot-yoga-classes-london')
def london_181():
    return render_template('landing_europe.html', data="hot yoga classes london")
@app.route('/german-classes-in-london')
def london_182():
    return render_template('landing_europe.html', data="german classes in london")
@app.route('/evening-classes-in-london')
def london_183():
    return render_template('landing_europe.html', data="evening classes in london")
@app.route('/nail-art-courses-london')
def london_184():
    return render_template('landing_europe.html', data="nail art courses london")
@app.route('/arabic-classes-in-london')
def london_185():
    return render_template('landing_europe.html', data="arabic classes in london")
@app.route('/cooking-classes-in-london-ontario')
def london_186():
    return render_template('landing_europe.html', data="cooking classes in london ontario")
@app.route('/ice-skating-classes-london')
def london_187():
    return render_template('landing_europe.html', data="ice skating classes london")
@app.route('/meditation-classes-in-london')
def london_188():
    return render_template('landing_europe.html', data="meditation classes in london")
@app.route('/cake-decorating-classes-in-london')
def london_189():
    return render_template('landing_europe.html', data="cake decorating classes in london")
@app.route('/zouk-classes-london')
def london_190():
    return render_template('landing_europe.html', data="zouk classes london")
@app.route('/mac-makeup-classes-london')
def london_191():
    return render_template('landing_europe.html', data="mac makeup classes london")
@app.route('/watercolour-classes-london')
def london_192():
    return render_template('landing_europe.html', data="watercolour classes london")
@app.route('/gmat-classes-london')
def london_193():
    return render_template('landing_europe.html', data="gmat classes london")
@app.route('/archery-courses-london')
def london_194():
    return render_template('landing_europe.html',data="archery courses london")
@app.route('/evening-cookery-classes-london')
def london_195():
    return render_template('landing_europe.html',data="evening cookery classes london")
@app.route('/rebounding-classes-london')
def london_196():
    return render_template('landing_europe.html',data="rebounding classes london")
@app.route('/irish-dancing-classes-london')
def london_197():
    return render_template('landing_europe.html',data="irish dancing classes london")
@app.route('/wedding-dance-classes-london')
def london_198():
    return render_template('landing_europe.html',data="wedding dance classes london")
@app.route('/japanese-cooking-classes-london')
def london_199():
    return render_template('landing_europe.html',data="japanese cooking classes london")
@app.route('/jazz-dance-classes-london')
def london_200():
    return render_template('landing_europe.html',data="jazz dance classes london")
@app.route('/ukulele-classes-london')
def london_201():
    return render_template('landing_europe.html',data="ukulele classes london")
@app.route('/kickboxing-classes-in-london')
def london_202():
    return render_template('landing_europe.html',data="kickboxing classes in london")
@app.route('/street-dance-classes-in-london')
def london_203():
    return render_template('landing_europe.html',data="street dance classes in london")
@app.route('/fun-classes-in-london')
def london_204():
    return render_template('landing_europe.html',data="fun classes in london")
@app.route('/house-dance-classes-london')
def london_205():
    return render_template('landing_europe.html',data="house dance classes london")
@app.route('/yoga-classes-in-london-ontario')
def london_206():
    return render_template('landing_europe.html',data="yoga classes in london ontario")
@app.route('/italian-classes-in-london')
def london_207():
    return render_template('landing_europe.html',data="italian classes in london")
@app.route('/zumba-classes-london-ontario')
def london_208():
    return render_template('landing_europe.html',data="zumba classes london ontario")
@app.route('/tango-classes-in-london')
def london_209():
    return render_template('landing_europe.html',data="tango classes in london")
@app.route('/line-dancing-classes-london')
def london_210():
    return render_template('landing_europe.html',data="line dancing classes london")
@app.route('/spinning-classes-in-london')
def london_211():
    return render_template('landing_europe.html',data="spinning classes in london")
@app.route('/urdu-classes-london')
def london_212():
    return render_template('landing_europe.html',data="urdu classes london")
@app.route('/yin-yoga-classes-london')
def london_213():
    return render_template('landing_europe.html',data="yin yoga classes london")
@app.route('/photography-classes-in-london')
def london_214():
    return render_template('landing_europe.html',data="photography classes in london")
@app.route('/les-mills-classes-london')
def london_215():
    return render_template('landing_europe.html',data="les mills classes london")
@app.route('/latin-classes-london')
def london_216():
    return render_template('landing_europe.html',data="latin classes london")
@app.route('/macaron-classes-london')
def london_217():
    return render_template('landing_europe.html',data="macaron classes london")
@app.route('/bollywood-dance-classes-in-london')
def london_218():
    return render_template('landing_europe.html',data="bollywood dance classes in london")
@app.route('/jiu-jitsu-classes-london')
def london_219():
    return render_template('landing_europe.html',data="jiu jitsu classes london")
@app.route('/dance-classes-london-bridge')
def london_220():
    return render_template('landing_europe.html',data="dance classes london bridge")
@app.route('/best-yoga-classes-in-london')
def london_221():
    return render_template('landing_europe.html',data="best yoga classes in london")
@app.route('/reggaeton-classes-london')
def london_222():
    return render_template('landing_europe.html',data="reggaeton classes london")
@app.route('/kung-fu-classes-in-london')
def london_223():
    return render_template('landing_europe.html',data="kung fu classes in london")
@app.route('/group-cooking-classes-london')
def london_224():
    return render_template('landing_europe.html',data="group cooking classes london")
@app.route('/raw-food-classes-london')
def london_225():
    return render_template('landing_europe.html',data="raw food classes london")
@app.route('/diy-classes-london')
def london_226():
    return render_template('landing_europe.html',data="diy classes london")
@app.route('/weekend-classes-london')
def london_227():
    return render_template('landing_europe.html',data="weekend classes london")
@app.route('/painting-classes-in-london')
def london_228():
    return render_template('landing_europe.html',data="painting classes in london")
@app.route('/reformer-pilates-classes-london')
def london_229():
    return render_template('landing_europe.html',data="reformer pilates classes london")
@app.route('/drawing-classes-in-london')
def london_230():
    return render_template('landing_europe.html',data="drawing classes in london")
@app.route('/open-dance-classes-london')
def london_231():
    return render_template('landing_europe.html',data="open dance classes london")
@app.route('/singing-classes-in-london')
def london_232():
    return render_template('landing_europe.html',data="singing classes in london")
@app.route('/martial-arts-classes-in-london')
def london_233():
    return render_template('landing_europe.html',data="martial arts classes in london")
@app.route('/contemporary-dance-classes-in-london')
def london_234():
    return render_template('landing_europe.html',data="contemporary dance classes in london")
@app.route('/hen-party-dance-classes-london')
def london_235():
    return render_template('landing_europe.html',data="hen party dance classes london")
@app.route('/tai-chi-classes-in-london')
def london_236():
    return render_template('landing_europe.html',data="tai chi classes in london")
@app.route('/northern-soul-dance-classes-london')
def london_237():
    return render_template('landing_europe.html',data="northern soul dance classes london")
@app.route('/quilting-classes-london')
def london_238():
    return render_template('landing_europe.html',data="quilting classes london")
@app.route('/gymnastics-classes-in-london')
def london_239():
    return render_template('landing_europe.html',data="gymnastics classes in london")
@app.route('/norwegian-classes-london')
def london_240():
    return render_template('landing_europe.html',data="norwegian classes london")
@app.route('/hatha-yoga-classes-london')
def london_241():
    return render_template('landing_europe.html',data="hatha yoga classes london")
@app.route('/free-dance-classes-in-london')
def london_242():
    return render_template('landing_europe.html',data="free dance classes in london")
@app.route('/life-drawing-classes-in-london')
def london_243():
    return render_template('landing_europe.html',data="life drawing classes in london")
@app.route('/greek-courses-london')
def london_244():
    return render_template('landing_europe.html',data="greek courses london")
@app.route('/karate-classes-in-london')
def london_245():
    return render_template('landing_europe.html',data="karate classes in london")
@app.route('/rowing-classes-london')
def london_246():
    return render_template('landing_europe.html',data="rowing classes london")
@app.route('/rock-and-roll-dance-classes-london')
def london_247():
    return render_template('landing_europe.html',data="rock and roll dance classes london")
@app.route('/self-defence-classes-in-london')
def london_248():
    return render_template('landing_europe.html',data="self defence classes in london")
@app.route('/free-yoga-classes-in-london')
def london_249():
    return render_template('landing_europe.html',data="free yoga classes in london")
@app.route('/hip-hop-dance-classes-in-london')
def london_250():
    return render_template('landing_europe.html',data="hip hop dance classes in london")
@app.route('/volleyball-classes-london')
def london_251():
    return render_template('landing_europe.html',data="volleyball classes london")
@app.route('/dance-classes-in-london-for-adults')
def london_252():
    return render_template('landing_europe.html',data="dance classes in london for adults")
@app.route('/nike-training-club-classes-london')
def london_253():
    return render_template('landing_europe.html',data="nike training club classes london")
@app.route('/chocolate-making-classes-in-london')
def london_254():
    return render_template('landing_europe.html',data="chocolate making classes in london")
@app.route('/make-up-classes-in-london')
def london_255():
    return render_template('landing_europe.html',data="make up classes in london")
@app.route('/krav-maga-classes-in-london')
def london_256():
    return render_template('landing_europe.html',data="krav maga classes in london")
@app.route('/yoruba-classes-london')
def london_257():
    return render_template('landing_europe.html',data="yoruba classes london")
@app.route('/english-speaking-classes-in-london')
def london_258():
    return render_template('landing_europe.html',data="english speaking classes in london")
@app.route('/wing-chun-classes-in-london')
def london_259():
    return render_template('landing_europe.html',data="wing chun classes in london")
@app.route('/dance-classes-in-london-ontario')
def london_260():
    return render_template('landing_europe.html',data="dance classes in london ontario")
@app.route('/drama-classes-in-london')
def london_261():
    return render_template('landing_europe.html',data="drama classes in london")
@app.route('/jujitsu-classes-london')
def london_262():
    return render_template('landing_europe.html',data="jujitsu classes london")
@app.route('/piano-classes-in-london')
def london_263():
    return render_template('landing_europe.html',data="piano classes in london")
@app.route('/kangoo-jumps-classes-in-london')
def london_264():
    return render_template('landing_europe.html',data="kangoo jumps classes in london")
@app.route('/belly-dancing-classes-in-london')
def london_265():
    return render_template('landing_europe.html',data="belly dancing classes in london")
@app.route('/art-classes-in-london-ontario')
def london_266():
    return render_template('landing_europe.html',data="art classes in london ontario")
@app.route('/ninjutsu-classes-london')
def london_267():
    return render_template('landing_europe.html',data="ninjutsu classes london")
@app.route('/urban-dance-classes-london')
def london_268():
    return render_template('landing_europe.html',data="urban dance classes london")
@app.route('/guitar-classes-in-london')
def london_269():
    return render_template('landing_europe.html',data="guitar classes in london")
@app.route('/portuguese-classes-in-london')
def london_270():
    return render_template('landing_europe.html',data="portuguese classes in london")
@app.route('/kathak-classes-in-london')
def london_271():
    return render_template('landing_europe.html',data="kathak classes in london")
@app.route('/vocal-classes-london')
def london_272():
    return render_template('landing_europe.html',data="vocal classes london")
@app.route('/graffiti-classes-london')
def london_273():
    return render_template('landing_europe.html',data="graffiti classes london")
@app.route('/rock-and-roll-classes-london')
def london_274():
    return render_template('landing_europe.html',data="rock and roll classes london")
@app.route('/jamie-oliver-classes-london')
def london_275():
    return render_template('landing_europe.html',data="jamie oliver classes london")
@app.route('/african-dance-classes-in-london')
def london_276():
    return render_template('landing_europe.html',data="african dance classes in london")
@app.route('/open-ballet-classes-london')
def london_277():
    return render_template('landing_europe.html',data="open ballet classes london")
@app.route('/origami-classes-london')
def london_278():
    return render_template('landing_europe.html',data="origami classes london")
@app.route('/yoga-classes-london-beginners')
def london_279():
    return render_template('landing_europe.html',data="yoga classes london beginners")
@app.route('/taekwondo-classes-in-london')
def london_280():
    return render_template('landing_europe.html',data="taekwondo classes in london")
@app.route('/exercise-classes-in-london')
def london_281():
    return render_template('landing_europe.html',data="exercise classes in london")
@app.route('/mma-classes-in-london')
def london_282():
    return render_template('landing_europe.html',data="mma classes in london")
@app.route('/flamenco-classes-in-london')
def london_283():
    return render_template('landing_europe.html',data="flamenco classes in london")
@app.route('/japanese-classes-in-london')
def london_284():
    return render_template('landing_europe.html',data="japanese classes in london")
@app.route('/language-classes-in-london')
def london_285():
    return render_template('landing_europe.html',data="language classes in london")
@app.route('/english-classes-in-london-free')
def london_286():
    return render_template('landing_europe.html',data="english classes in london free")
@app.route('/outdoor-fitness-classes-london')
def london_287():
    return render_template('landing_europe.html',data="outdoor fitness classes london")
@app.route('/zouk-dance-classes-london')
def london_288():
    return render_template('landing_europe.html',data="zouk dance classes london")
@app.route('/loblaws-cooking-classes-london-ontario')
def london_289():
    return render_template('landing_europe.html',data="loblaws cooking classes london ontario")
@app.route('/gym-classes-in-london')
def london_290():
    return render_template('landing_europe.html',data="gym classes in london")
@app.route('/music-classes-in-london')
def london_291():
    return render_template('landing_europe.html',data="music classes in london")
@app.route('/violin-classes-in-london')
def london_292():
    return render_template('landing_europe.html',data="violin classes in london")
@app.route('/wedding-cake-decorating-classes-london')
def london_293():
    return render_template('landing_europe.html',data="wedding cake decorating classes london")
@app.route('/rhythmic-gymnastics-classes-london')
def london_294():
    return render_template('landing_europe.html',data="rhythmic gymnastics classes london")
@app.route('/life-drawing-classes-london-evening')
def london_295():
    return render_template('landing_europe.html',data="life drawing classes london evening")
@app.route('/hindi-classes-in-london')
def london_296():
    return render_template('landing_europe.html',data="hindi classes in london")
@app.route('/zumba-classes-in-london-ontario')
def london_297():
    return render_template('landing_europe.html',data="zumba classes in london ontario")
@app.route('/muay-thai-classes-in-london')
def london_298():
    return render_template('landing_europe.html',data="muay thai classes in london")
@app.route('/hebrew-classes-in-london')
def london_299():
    return render_template('landing_europe.html',data="hebrew classes in london")
@app.route('/knitting-classes-in-london')
def london_300():
    return render_template('landing_europe.html',data="knitting classes in london")
@app.route('/voice-over-classes-london')
def london_301():
    return render_template('landing_europe.html',data="voice over classes london")
@app.route('/classes-in-london-ontario')
def london_302():
    return render_template('landing_europe.html',data="classes in london ontario")
@app.route('/relaxation-courses-london')
def london_303():
    return render_template('landing_europe.html',data="relaxation courses london")
@app.route('/bachata-classes-in-london')
def london_304():
    return render_template('landing_europe.html',data="bachata classes in london")
@app.route('/unusual-classes-london')
def london_305():
    return render_template('landing_europe.html',data="unusual classes london")
@app.route('/tap-classes-in-london')
def london_306():
    return render_template('landing_europe.html',data="tap classes in london")
@app.route('/shiamak-davar-dance-classes-in-london')
def london_307():
    return render_template('landing_europe.html',data="shiamak davar dance classes in london")
@app.route('/trx-classes-in-london')
def london_308():
    return render_template('landing_europe.html',data="trx classes in london")
@app.route('/reiki-classes-in-london')
def london_309():
    return render_template('landing_europe.html',data="reiki classes in london")
@app.route('/cake-baking-classes-in-london')
def london_310():
    return render_template('landing_europe.html',data="cake baking classes in london")
@app.route('/bhangra-classes-in-london')
def london_311():
    return render_template('landing_europe.html',data="bhangra classes in london")
@app.route('/yo-sushi-classes-london')
def london_312():
    return render_template('landing_europe.html',data="yo sushi classes london")
@app.route('/writing-classes-in-london')
def london_313():
    return render_template('landing_europe.html',data="writing classes in london")
@app.route('/indian-dance-classes-in-london')
def london_314():
    return render_template('landing_europe.html',data="indian dance classes in london")
@app.route('/yoga-nidra-classes-london')
def london_315():
    return render_template('landing_europe.html',data="yoga nidra classes london")
@app.route('/indian-cooking-classes-in-london')
def london_316():
    return render_template('landing_europe.html',data="indian cooking classes in london")
@app.route('/craft-classes-in-london')
def london_317():
    return render_template('landing_europe.html',data="craft classes in london")
@app.route('/opera-classes-london')
def london_318():
    return render_template('landing_europe.html',data="opera classes london")
@app.route('/tennis-classes-in-london')
def london_319():
    return render_template('landing_europe.html',data="tennis classes in london")
@app.route('/burlesque-classes-in-london')
def london_320():
    return render_template('landing_europe.html',data="burlesque classes in london")
@app.route('/hobby-classes-in-london')
def london_321():
    return render_template('landing_europe.html',data="hobby classes in london")
@app.route('/insanity-classes-in-london')
def london_322():
    return render_template('landing_europe.html',data="insanity classes in london")
@app.route('/weekend-english-classes-in-london')
def london_323():
    return render_template('landing_europe.html',data="weekend english classes in london")
@app.route('/nct-courses-london')
def london_324():
    return render_template('landing_europe.html',data="nct courses london")
@app.route('/ufc-classes-london')
def london_325():
    return render_template('landing_europe.html',data="ufc classes london")
@app.route('/fencing-classes-in-london')
def london_326():
    return render_template('landing_europe.html',data="fencing classes in london")
@app.route('/vietnamese-cooking-classes-london')
def london_327():
    return render_template('landing_europe.html',data="vietnamese cooking classes london")
@app.route('/tumbling-classes-in-london')
def london_328():
    return render_template('landing_europe.html',data="tumbling classes in london")
@app.route('/prenatal-classes-in-london-ontario')
def london_329():
    return render_template('landing_europe.html',data="prenatal classes in london ontario")
@app.route('/yoga-classes-in-london-bridge')
def london_330():
    return render_template('landing_europe.html',data="yoga classes in london bridge")
@app.route('/vinyasa-yoga-classes-london')
def london_331():
    return render_template('landing_europe.html',data="vinyasa yoga classes london")
@app.route('/nia-classes-london')
def london_332():
    return render_template('landing_europe.html',data="nia classes london")
@app.route('/dog-training-classes-in-london')
def london_333():
    return render_template('landing_europe.html',data="dog training classes in london")
@app.route('/quran-classes-in-london')
def london_334():
    return render_template('landing_europe.html',data="quran classes in london")
@app.route('/netball-classes-london')
def london_335():
    return render_template('landing_europe.html',data="netball classes london")
@app.route('/night-classes-in-london')
def london_336():
    return render_template('landing_europe.html',data="night classes in london")
@app.route('/xtend-barre-classes-london')
def london_337():
    return render_template('landing_europe.html',data="xtend barre classes london")
@app.route('/mandarin-classes-in-london')
def london_338():
    return render_template('landing_europe.html',data="mandarin classes in london")
@app.route('/ninjutsu-classes-in-london')
def london_339():
    return render_template('landing_europe.html',data="ninjutsu classes in london")
@app.route('/one-day-cookery-classes-london')
def london_340():
    return render_template('landing_europe.html',data="one day cookery classes london")
@app.route('/yoga-classes-london-city')
def london_341():
    return render_template('landing_europe.html',data="yoga classes london city")
@app.route('/pottery-classes-in-london-ontario')
def london_342():
    return render_template('landing_europe.html',data="pottery classes in london ontario")
@app.route('/acting-classes-london-16+')
def london_343():
    return render_template('landing_europe.html',data="acting classes london 16+")
@app.route('/acting-classes-in-london-ontario')
def london_344():
    return render_template('landing_europe.html',data="acting classes in london ontario")
@app.route('/etiquette-classes-in-london')
def london_345():
    return render_template('landing_europe.html',data="etiquette classes in london")
@app.route('/dance-classes-for-over-50s-london')
def london_346():
    return render_template('landing_europe.html',data="dance classes for over 50s london")
@app.route('/jeet-kune-do-classes-in-london')
def london_347():
    return render_template('landing_europe.html',data="jeet kune do classes in london")
@app.route('/esl-classes-in-london-ontario')
def london_348():
    return render_template('landing_europe.html',data="esl classes in london ontario")
@app.route('/hot-yoga-classes-in-london')
def london_349():
    return render_template('landing_europe.html',data="hot yoga classes in london")
@app.route('/russian-classes-in-london')
def london_350():
    return render_template('landing_europe.html',data="russian classes in london")
@app.route('/line-dancing-classes-in-london')
def london_351():
    return render_template('landing_europe.html',data="line dancing classes in london")
@app.route('/horse-riding-classes-in-london')
def london_352():
    return render_template('landing_europe.html',data="horse riding classes in london")
@app.route('/wrestling-classes-in-london')
def london_353():
    return render_template('landing_europe.html',data="wrestling classes in london")
@app.route('/jive-classes-in-london')
def london_354():
    return render_template('landing_europe.html',data="jive classes in london")
@app.route('/judo-classes-in-london')
def london_355():
    return render_template('landing_europe.html',data="judo classes in london")
@app.route('/one-day-dance-classes-london')
def london_356():
    return render_template('landing_europe.html',data="one day dance classes london")
@app.route('/indian-classical-dance-classes-in-london')
def london_357():
    return render_template('landing_europe.html',data="indian classical dance classes in london")
@app.route('/pole-dancing-classes-in-london-ontario')
def london_358():
    return render_template('landing_europe.html',data="pole dancing classes in london ontario")
@app.route('/urdu-classes-in-london')
def london_359():
    return render_template('landing_europe.html',data="urdu classes in london")
@app.route('/driving-classes-in-london')
def london_360():
    return render_template('landing_europe.html',data="driving classes in london")
@app.route('/latin-dance-classes-in-london')
def london_361():
    return render_template('landing_europe.html',data="latin dance classes in london")
@app.route('/antenatal-classes-in-london')
def london_362():
    return render_template('landing_europe.html',data="antenatal classes in london")
@app.route('/english-conversation-classes-in-london')
def london_363():
    return render_template('landing_europe.html',data="english conversation classes in london")
@app.route('/veena-classes-in-london')
def london_364():
    return render_template('landing_europe.html',data="veena classes in london")
@app.route('/esol-classes-in-london')
def london_365():
    return render_template('landing_europe.html',data="esol classes in london")
@app.route('/turkish-classes-in-london')
def london_366():
    return render_template('landing_europe.html',data="turkish classes in london")
@app.route('/vegetarian-cooking-classes-london-uk')
def london_367():
    return render_template('landing_europe.html',data="vegetarian cooking classes london uk")
@app.route('/dance-classes-in-london-for-beginners')
def london_368():
    return render_template('landing_europe.html',data="dance classes in london for beginners")
@app.route('/cupcake-classes-in-london')
def london_369():
    return render_template('landing_europe.html',data="cupcake classes in london")
@app.route('/vegetarian-cooking-classes-in-london')
def london_370():
    return render_template('landing_europe.html',data="vegetarian cooking classes in london")
@app.route('/free-exercise-classes-in-london')
def london_371():
    return render_template('landing_europe.html',data="free exercise classes in london")
@app.route('/lindy-hop-classes-in-london')
def london_372():
    return render_template('landing_europe.html',data="lindy hop classes in london")
@app.route('/jewellery-making-classes-in-london')
def london_373():
    return render_template('landing_europe.html',data="jewellery making classes in london")
@app.route('/gmat-classes-in-london')
def london_374():
    return render_template('landing_europe.html',data="gmat classes in london")
@app.route('/macaron-classes-in-london')
def london_375():
    return render_template('landing_europe.html',data="macaron classes in london")
@app.route('/aikido-classes-in-london')
def london_376():
    return render_template('landing_europe.html',data="aikido classes in london")
@app.route('/evening-english-classes-in-london')
def london_377():
    return render_template('landing_europe.html',data="evening english classes in london")
@app.route('/sushi-classes-in-london')
def london_378():
    return render_template('landing_europe.html',data="sushi classes in london")
@app.route('/gymboree-classes-london')
def london_379():
    return render_template('landing_europe.html',data="gymboree classes london")
@app.route('/metafit-classes-london')
def london_380():
    return render_template('landing_europe.html',data="metafit classes london")
@app.route('/yoga-classes-in-london-uk')
def london_381():
    return render_template('landing_europe.html',data="yoga classes in london uk")
@app.route('/italian-cooking-classes-in-london')
def london_382():
    return render_template('landing_europe.html',data="italian cooking classes in london")
@app.route('/dancehall-classes-in-london')
def london_383():
    return render_template('landing_europe.html',data="dancehall classes in london")
@app.route('/islamic-classes-in-london')
def london_384():
    return render_template('landing_europe.html',data="islamic classes in london")
@app.route('/quranic-arabic-classes-london')
def london_385():
    return render_template('landing_europe.html',data="quranic arabic classes london")
@app.route('/jiu-jitsu-classes-in-london')
def london_386():
    return render_template('landing_europe.html',data="jiu jitsu classes in london")
@app.route('/qigong-classes-london-uk')
def london_387():
    return render_template('landing_europe.html',data="qigong classes london uk")
@app.route('/wushu-classes-in-london')
def london_388():
    return render_template('landing_europe.html',data="wushu classes in london")
@app.route('/samba-classes-in-london')
def london_389():
    return render_template('landing_europe.html',data="samba classes in london")
@app.route('/quran-classes-in-east-london')
def london_390():
    return render_template('landing_europe.html',data="quran classes in east london")
@app.route('/weekend-classes-in-london')
def london_391():
    return render_template('landing_europe.html',data="weekend classes in london")
@app.route('/tap-dancing-classes-in-london')
def london_392():
    return render_template('landing_europe.html',data="tap dancing classes in london")
@app.route('/kickboxing-classes-in-london-ontario')
def london_393():
    return render_template('landing_europe.html',data="kickboxing classes in london ontario")
@app.route('/glass-blowing-classes-in-london')
def london_394():
    return render_template('landing_europe.html',data="glass blowing classes in london")
@app.route('/ninja-classes-london')
def london_395():
    return render_template('landing_europe.html',data="ninja classes london")
@app.route('/hula-hoop-classes-in-london')
def london_396():
    return render_template('landing_europe.html',data="hula hoop classes in london")
@app.route('/les-mills-classes-in-london')
def london_397():
    return render_template('landing_europe.html',data="les mills classes in london")
@app.route('/william-curley-chocolate-classes-in-london')
def london_398():
    return render_template('landing_europe.html',data="william curley chocolate classes in london")
@app.route('/1920s-dance-classes-london')
def london_399():
    return render_template('landing_europe.html',data="1920s dance classes london")
@app.route('/jamie-oliver-cooking-classes-in-london')
def london_400():
    return render_template('landing_europe.html',data="jamie oliver cooking classes in london")
@app.route('/rhythmic-gymnastics-classes-in-london')
def london_401():
    return render_template('landing_europe.html',data="rhythmic gymnastics classes in london")
@app.route('/kettlebell-classes-in-london')
def london_402():
    return render_template('landing_europe.html',data="kettlebell classes in london")
@app.route('/1-day-cooking-classes-london')
def london_403():
    return render_template('landing_europe.html',data="1 day cooking classes london")
@app.route('/ice-skating-classes-in-london')
def london_404():
    return render_template('landing_europe.html',data="ice skating classes in london")
@app.route('/quilting-classes-in-london')
def london_405():
    return render_template('landing_europe.html',data="quilting classes in london")
@app.route('/tajweed-classes-in-london')
def london_406():
    return render_template('landing_europe.html',data="tajweed classes in london")
@app.route('/jazz-dance-classes-in-london')
def london_407():
    return render_template('landing_europe.html',data="jazz dance classes in london")
@app.route('/oil-painting-classes-in-london')
def london_408():
    return render_template('landing_europe.html',data="oil painting classes in london")
@app.route('/qigong-classes-in-london')
def london_409():
    return render_template('landing_europe.html',data="qigong classes in london")
@app.route('/jujitsu-classes-in-london')
def london_410():
    return render_template('landing_europe.html',data="jujitsu classes in london")
@app.route('/dressmaking-classes-in-london')
def london_411():
    return render_template('landing_europe.html',data="dressmaking classes in london")
@app.route('/nordic-walking-classes-london')
def london_412():
    return render_template('landing_europe.html',data="nordic walking classes london")
@app.route('/zumba-classes-london-colney')
def london_413():
    return render_template('landing_europe.html',data="zumba classes london colney")
@app.route('/butchery-classes-in-london')
def london_414():
    return render_template('landing_europe.html',data="butchery classes in london")
@app.route('/norwegian-classes-in-london')
def london_415():
    return render_template('landing_europe.html',data="norwegian classes in london")
@app.route('/japanese-cooking-classes-in-london')
def london_416():
    return render_template('landing_europe.html',data="japanese cooking classes in london")
@app.route('/vibration-plate-classes-london')
def london_417():
    return render_template('landing_europe.html',data="vibration plate classes london")
@app.route('/latin-classes-in-london')
def london_418():
    return render_template('landing_europe.html',data="latin classes in london")
@app.route('/hip-hop-dance-classes-in-london-ontario')
def london_419():
    return render_template('landing_europe.html',data="hip hop dance classes in london ontario")
@app.route('/womens-boxing-classes-in-london')
def london_420():
    return render_template('landing_europe.html',data="womens boxing classes in london")
@app.route('/open-dance-classes-in-london')
def london_421():
    return render_template('landing_europe.html',data="open dance classes in london")
@app.route('/yoga-swing-classes-london')
def london_422():
    return render_template('landing_europe.html',data="yoga swing classes london")
@app.route('/50s-dance-classes-london')
def london_423():
    return render_template('landing_europe.html',data="50s dance classes london")
@app.route('/upholstery-classes-in-london')
def london_424():
    return render_template('landing_europe.html',data="upholstery classes in london")
@app.route('/hifz-classes-in-london')
def london_425():
    return render_template('landing_europe.html',data="hifz classes in london")
@app.route('/odissi-dance-classes-in-london')
def london_426():
    return render_template('landing_europe.html',data="odissi dance classes in london")
@app.route('/water-aerobics-classes-in-london')
def london_427():
    return render_template('landing_europe.html',data="water aerobics classes in london")
@app.route('/raw-food-classes-in-london')
def london_428():
    return render_template('landing_europe.html',data="raw food classes in london")
@app.route('/one-day-cookery-classes-in-london')
def london_429():
    return render_template('landing_europe.html',data="one day cookery classes in london")
@app.route('/yoruba-classes-in-london')
def london_430():
    return render_template('landing_europe.html',data="yoruba classes in london")
@app.route('/volleyball-classes-in-london')
def london_431():
    return render_template('landing_europe.html',data="volleyball classes in london")
@app.route('/latin-and-ballroom-dance-classes-in-london')
def london_432():
    return render_template('landing_europe.html',data="latin and ballroom dance classes in london")
@app.route('/80s-dance-classes-london')
def london_433():
    return render_template('landing_europe.html',data="80s dance classes london")
@app.route('/zumba-classes-london-nw')
def london_434():
    return render_template('landing_europe.html',data="zumba classes london nw")
@app.route('/latin-american-dance-classes-in-london')
def london_435():
    return render_template('landing_europe.html',data="latin american dance classes in london")
@app.route('/gujarati-classes-in-london')
def london_436():
    return render_template('landing_europe.html',data="gujarati classes in london")
@app.route('/ballet-classes-for-2-year-olds-in-london')
def london_437():
    return render_template('landing_europe.html',data="ballet classes for 2 year olds in london")
@app.route('/nia-classes-in-london')
def london_438():
    return render_template('landing_europe.html',data="nia classes in london")
@app.route('/free-classes-london-2016')
def london_439():
    return render_template('landing_europe.html',data="free classes london 2016")
@app.route('/gymnastics-classes-in-london-for-adults')
def london_440():
    return render_template('landing_europe.html',data="gymnastics classes in london for adults")
@app.route('/urban-dance-classes-in-london')
def london_441():
    return render_template('landing_europe.html',data="urban dance classes in london")
@app.route('/zumba-gold-classes-london')
def london_442():
    return render_template('landing_europe.html',data="zumba gold classes london")
@app.route('/hydrospin-classes-in-london')
def london_443():
    return render_template('landing_europe.html',data="hydrospin classes in london")
@app.route('/zumba-classes-london-e14')
def london_444():
    return render_template('landing_europe.html',data="zumba classes london e14")
@app.route('/london-evening-classes-2016')
def london_445():
    return render_template('landing_europe.html',data="london evening classes 2016")
@app.route('/zumba-classes-london-sw')
def london_446():
    return render_template('landing_europe.html',data="zumba classes london sw")
@app.route('/gcse-evening-classes-in-london')
def london_447():
    return render_template('landing_europe.html',data="gcse evening classes in london")
@app.route('/free-art-classes-london-2016')
def london_448():
    return render_template('landing_europe.html',data="free art classes london 2016")
@app.route('/free-classes-london-2016')
def london_449():
    return render_template('landing_europe.html',data="free classes london 2016")