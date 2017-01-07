"""Forms to render HTML input & validate request data."""

from wtforms import Form, BooleanField, DateTimeField, PasswordField
from wtforms import TextAreaField, TextField, StringField, SubmitField
from wtforms.validators import Length, required, Required, EqualTo, ValidationError
from flask_security.forms import RegisterForm

def my_length_check(form, field):
    if len(field.data) < 6:
        raise ValidationError('Password must greater than 6 characters')
class CoachRegisterForm(RegisterForm):
    password = PasswordField('password', [Required(), my_length_check])
    first_name = TextField('Your name', [Length(max=255), Required()])
    email = TextField('E-mail', [Length(max=255), Required()])

 


class ExtendedRegisterForm(RegisterForm):
    name = TextField('Name', [Required()])
    coach = BooleanField('This is coach account')



# # Custom validators to check if user or email already exists
# def validate_user(form, field):
#   if db.session.query(User).filter_by(username=form.username.data).count() > 0:
#     raise validators.ValidationError('Username already exists')
#
# def validate_email(form, field):
#   if db.session.query(User).filter_by(email=form.email.data).count() > 0:
#     raise validators.ValidationError('Email already in use')
#
#
# class SignupForm(Form):
#   username = TextField('username', validators = [Required(), validate_user])
#   password = PasswordField('password', [
#     Required(message='Password cannot be empty'),
#     EqualTo('confirm', message='Passwords did not match'),
#     Length(min=8, max=100, message='Password too short')
#   ])
#   confirm = PasswordField('Repeat password', validators = [Required()])

class ResumeForm(Form):
  
    """Render HTML input for Resume model & validate submissions.

    This matches the models.Resume class very closely. Where
    models.Resume represents the domain and its persistence, this class
    represents how to display a form in HTML & accept/reject the results.
    """



    #NEW FIELDS TO ADD INTO THE SYSTEM
    name = TextField('Name', [Length(max=255), Required()])
    email = TextField('Email', [Length(max=100), Required()])
    phone = TextField('Phone', [Length(max=255), Required()])
    city = TextField('City', [Length(max=100), Required()])
    zip = TextField('Zip', [Length(max=50), Required()])
    country = TextField('City', [Length(max=255), Required()])
    summary_text = TextAreaField('What kind of learning outcomes are you looking for?', [Length(max=500)])
    want_one = TextField('Course or class you are interested in', [Length(max=255)])
    want_two = TextField('Course or class you are interested in', [Length(max=255)])
    want_three = TextField('Course or class you are interested in', [Length(max=255)])
    want_four = TextField('Course or class you are interested in', [Length(max=255)])
    want_five = TextField('Course or class you are interested in', [Length(max=255)])
    want_six = TextField('Course or class you are interested in', [Length(max=255)])





class CourseForm(Form):
    course_title = TextField('Course title', [Length(max=255)])
    cost_per_hour = TextField('5 or 10 or 25 , no currencies', [Length(max=3), Required()])
    rent_per_hour = TextField('5 or 10 or 25 , no currencies', [Length(max=3), Required()])
    coach_name = TextField('Coach name', [Length(max=255)])
    city = TextField('City', [Length(max=100), Required()])
    zip = TextField('Zip code', [Length(max=50), Required()])
    country = TextField('Country', [Length(max=255), Required()])
    street_address = TextField('Course Venue', [Length(max=255)])
    why_description = TextAreaField('Description', [Required()])
    prerequisites_requirements = TextAreaField('Description', [Required()])
    course_module_one = TextField('Course Module', [Length(max=255)])
    module_one_description = TextAreaField('Description', [Required()])
    course_module_two = TextField('Course Module', [Length(max=255)])
    module_two_description = TextAreaField('Description', [Required()])
    course_module_three = TextField('Course Module', [Length(max=255)])
    module_three_description = TextAreaField('Description', [Required()])
    course_module_four = TextField('Course Module', [Length(max=255)])
    module_four_description = TextAreaField('Description', [Required()])
    course_module_five = TextField('Course Module', [Length(max=255)])
    module_five_description = TextAreaField('Description', [Required()])
    course_module_six = TextField('Course Module', [Length(max=255)])
    module_six_description = TextAreaField('Description')
    course_module_seven = TextField('Course Module', [Length(max=255)])
    module_seven_description = TextAreaField('Description')
    course_module_eight = TextField('Course Module', [Length(max=255)])
    module_eight_description = TextAreaField('Description')
    course_module_nine = TextField('Course Module', [Length(max=255)])
    module_nine_description = TextAreaField('Description')
    course_module_ten = TextField('Course Module', [Length(max=255)])
    module_ten_description = TextAreaField('Description')
    course_start_date = TextField('Course Start Date', [Length(max=255), Required()])
    course_end_date = TextField('Course End Date', [Length(max=255), Required()])
    course_start_hour = TextField('Course Start Hour', [Length(max=255), Required()])
    course_end_hour = TextField('Course End Hour', [Length(max=255), Required()])
    hours_per_month = TextField('Total Hours Per Month', [Length(max=3), Required()])
    max_students = TextField('Maximum Students', [Length(max=3), Required()])
    min_students = TextField('Minmum Students', [Length(max=3), Required()])
    level = TextField('Certificate Level', [Length(max=2), Required()])
    #start_date = DateTimeField('Start Date', [Required()])
    #stop_date = DateTimeField('Stop Date', [Required()])
    bio_of_teacher = TextAreaField('Description', [Required()])

class RegisterCoachForm(Form):
    first_name = TextField('Your name', [Length(max=255), Required()])
    last_name = TextField('Last name', [Length(max=255), Required()])
    email = TextField('E-mail', [Length(max=255), Required()])
    website = TextField('Website if available', [Length(max=255) ])
    coach_name = TextField('Company name if a company or instituition', [Length(max=255)])
    coach_address = TextAreaField('Address', [Required()])
    phone_number = TextField('Phone number', [Length(max=255), Required()])
    additional_data1 = TextField('Class you teach', [Length(max=255), Required()])
    additional_data2 = TextField('Class you teach', [Length(max=255)])
    additional_data3 = TextField('Class you teach', [Length(max=255)])
    additional_data4 = TextField('Class you teach', [Length(max=255)])
    additional_data5 = TextField('Class you teach', [Length(max=255)])
class ContactForm(Form):
    subject = TextField('Message subject', [Length(max=255), Required()])
    text = TextAreaField('Message text', [Required()])



class SearchForm(Form):
    course_title = StringField('Course Title')
    cost_per_hour = StringField('Cost Per Hour')
    city = StringField('City')
    zip = StringField('Zip')
    country = StringField('Country')
    search = SubmitField('Search')
# class LoginForm(Form):
#     """Render HTML input for user login form.
#
#     Authentication (i.e. password verification) happens in the view function.
#     """
#     username = TextField('Username', [required()])
#     password = PasswordField('Password', [required()])
