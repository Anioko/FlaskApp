"""Domain models for an appointment scheduler, using pure SQLAlchemy."""

from datetime import datetime

from flask.ext.security import UserMixin, RoleMixin

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship, synonym, backref
from sqlalchemy.sql import select

from werkzeug import check_password_hash, generate_password_hash

from common import db

ROLE_ADMIN = 0
ROLE_USER = 1
ROLE_COACH = 2
ROLE_STUDENT = 3

roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

courses_users = db.Table('courses_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('course_id', db.Integer(), db.ForeignKey('Courses.id')))

class Role(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    description = Column(String(255))

    def __str__(self):
        return self.name

class User(db.Model, UserMixin):
    """A user login, with credentials and authentication."""
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password = Column('password', String(255))

    # Falsk-Security
    active = Column(Boolean())
    confirmed_at = Column(DateTime())
    #role_id = Column(Integer, ForeignKey('role.id'), )
    roles = relationship('Role', secondary=roles_users,
                            backref=backref('user', lazy='dynamic'))


    created = Column(DateTime, default=datetime.now)
    modified = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    name = Column('name', String(200))
    coach = Column(Boolean(), default=False)

    def __unicode__(self):
        return u"{0} uID:<{1}>".format(self.name, self.id)

class Resume(db.Model):
    """CV's."""
    __tablename__ = 'resumes'

    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.now)
    modified = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    user = relationship(User, lazy='joined', join_depth=1, viewonly=True)
    
    name = Column(String(255), default="")
    email = Column(String(100), default="")
    phone = Column(String(255), default="")
    city = Column(String(100), default="")
    zip = Column(String(50), default="")
    country = Column(String(255), default="")
    
    summary_text = Column(String(500), default="")
    want_one = Column(String(255), default="")
    want_two = Column(String(255), default="")
    want_three = Column(String(255), default="")
    want_four = Column(String(255), default="")
    want_five = Column(String(255), default="")
    want_six = Column(String(255), default="")
    def __repr__(self):
        return u'<{self.__class__.__name__}: {self.id}>'.format(self=self)





class Course(db.Model):
    """An appointment on the calendar."""
    __tablename__ = 'Courses'

    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.now)
    modified = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    user = relationship(User, lazy='joined', join_depth=1, viewonly=True)

    coach_name = Column(String(255))
    city = Column(String(255))
    zip = Column(String(255))
    country = Column(String(255))
    street_address = Column(String(255))
    #start_date = Column(DateTime, default=datetime.now, nullable=False)
    #stop_date = Column(DateTime, default=datetime.now, nullable=False)


    course_title = Column(String(255))
    cost_per_hour = Column(Integer)
    course_module_one = Column(String(255))
    course_module_two = Column(String(255))
    course_module_three = Column(String(255))
    course_module_four = Column(String(255))
    course_module_five = Column(String(255))
    course_module_six = Column(String(255))
    course_module_seven = Column(String(255))
    course_module_eight = Column(String(255))
    course_module_nine = Column(String(255))
    course_module_ten = Column(String(255))
    course_start_date = Column(String(255))
    course_end_date = Column(String(255))
    hours_per_week = Column(Integer)
    max_students = Column(Integer)
    min_students = Column(Integer)
    description = Column(Text)

    users = relationship('User', secondary=courses_users,
                            backref=backref('User', lazy='dynamic'))

    def __repr__(self):
        return u'<{self.__class__.__name__}: {self.id}>'.format(self=self)

class Oauth(db.Model):
    __tablename__ = 'oauth'
    id = Column(Integer, primary_key=True)
    provider = Column(String(255))
    provider_id = Column(String(255))
    email = Column(String(255))
    profile = Column(String(),nullable=True)

    additional_data1 = Column(String(),nullable=True)
    additional_data2 = Column(String(),nullable=True)
    additional_data3 = Column(String(),nullable=True)
    additional_data4 = Column(String(),nullable=True)
    additional_data5 = Column(String(),nullable=True)

    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')


class CoachUserData(db.Model):
    __tablename__ = 'coach_user_data'
    id = Column(Integer, primary_key=True,)
    first_name = Column(String(255))
    last_name = Column(String(255))
    email = Column(String(255))
    website = Column(String(255))
    coach_name = Column(String(255))
    coach_address = Column(String(),nullable=True)
    phone_number = Column(String(255))

    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')
    additional_data1 = Column(String(),nullable=True)
    additional_data2 = Column(String(),nullable=True)
    additional_data3 = Column(String(),nullable=True)
    additional_data4 = Column(String(),nullable=True)
    additional_data5 = Column(String(),nullable=True)

class ResumeView(db.Model):
    __tablename__ = 'resume_view'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now)

    user_id = Column(Integer, ForeignKey(User.id))
    resume_id = Column(Integer, ForeignKey(Resume.id))

    user = relationship('User', foreign_keys='ResumeView.user_id')
    resume = relationship('Resume', foreign_keys='ResumeView.resume_id')

    def __init__(self, user=None, resume=None):
        print "init", user, resume
        self.timestamp = datetime.now()
        self.user = user
        self.resume = resume


if __name__ == '__main__':
    from datetime import timedelta

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # This uses a SQLite database in-memory.
    #
    # That is, this uses a database which only exists for the duration of
    # Python's process execution, and will not persist across calls to Python.
    engine = create_engine('sqlite://', echo=True)

    # Create the database tables if they do not exist, and prepare a session.
    #
    # The engine connects to the database & executes queries. The session
    # represents an on-going conversation with the database and is the primary
    # entry point for applications to use a relational database in SQLAlchemy.
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Add a sample user.
    user = User(name='Ron DuPlain',
                email='ron.duplain@gmail.com',
                password='secret')
    session.add(user)
    session.commit()

    now = datetime.now()

    # Add some sample appointments.
    session.add(Appointment(
        user_id=user.id,
        title='Important Meeting',
        start=now + timedelta(days=3),
        end=now + timedelta(days=3, seconds=3600),
        allday=False,
        location='The Office'))
    session.commit()

    session.add(Appointment(
        user_id=user.id,
        title='Past Meeting',
        start=now - timedelta(days=3, seconds=3600),
        end=now - timedelta(days=3),
        allday=False,
        location='The Office'))
    session.commit()

    session.add(Appointment(
        user_id=user.id,
        title='Follow Up',
        start=now + timedelta(days=4),
        end=now + timedelta(days=4, seconds=3600),
        allday=False,
        location='The Office'))
    session.commit()

    session.add(Appointment(
        user_id=user.id,
        title='Day Off',
        start=now + timedelta(days=5),
        end=now + timedelta(days=5),
        allday=True))
    session.commit()

    # Create, update, delete.
    appt = Appointment(
        user_id=user.id,
        title='My Appointment',
        start=now,
        end=now + timedelta(seconds=1800),
        allday=False)

    # Create.
    session.add(appt)
    session.commit()

    # Update.
    appt.title = 'Your Appointment'
    session.commit()

    # Delete.
    session.delete(appt)
    session.commit()

    # Demonstration Queries

    # Each `appt` example is a Python object of type Appointment.
    # Each `appts` example is a Python list of Appointment objects.

    # Get an appointment by ID.
    appt = session.query(Appointment).get(1)

    # Get all appointments.
    appts = session.query(Appointment).all()

    # Get all appointments before right now, after right now.
    appts = session.query(Appointment).filter(Appointment.start < datetime.now()).all()
    appts = session.query(Appointment).filter(Appointment.start >= datetime.now()).all()

    # Get all appointments before a certain date.
    appts = session.query(Appointment).filter(Appointment.start <= datetime(2013, 5, 1)).all()

    # Get the first appointment matching the filter query.
    appt = session.query(Appointment).filter(Appointment.start <= datetime(2013, 5, 1)).first()

