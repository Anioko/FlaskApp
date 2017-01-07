from flask.ext.script import Manager

from teacheraApp import app, db, user_datastore
from teacheraApp import Role, Resume


# By default, Flask-Script adds the 'runserver' and 'shell' commands to
# interact with the Flask application. Add additional commands using the
# `@manager.command` decorator, where Flask-Script will create help
# documentation using the function's docstring. Try it, and call `python
# manage.py -h` to see the outcome.
manager = Manager(app)


@manager.command
def create_tables():
    "Create relational database tables."
    db.create_all()
    

@manager.command
def create_roles():
    db.session.add(Role(name='ROLE_ADMIN', description='admin'))
    db.session.add(Role(name='ROLE_USER', description='user'))
    db.session.add(Role(name='ROLE_COACH', description='coach'))
    db.session.add(Role(name='ROLE_STUDENT', description='attendee'))
    db.session.commit()


@manager.command
def drop_tables():
    "Drop all project relational database tables. THIS DELETES DATA."
    db.drop_all()

@manager.option('-i', '--id', help='User id or email')
def add_admin(id):
    user = user_datastore.get_user(id)
    role = user_datastore.find_role('ROLE_ADMIN')
    user_datastore.add_role_to_user(user, role)
    db.session.commit()

@manager.command
def upgrade_resumes():
    resumes = db.session.query(Resume).all()
    print resumes

    for resume in resumes:
        if resume.other_skills:
            continue

        print "Upgrading resume.id: ", resume.id

        resume.city = resume.country
        resume.start_date_coach = resume.start
        resume.end_date_coach  = resume.end
        resume.work_currently = resume.currently
        resume.location_coach = resume.location


        resume.start_date_coach1 = resume.coach_name_two
        resume.coach_name1 = resume.coach_name_two
        resume.coach_summary1 = resume.coach_summary_two
        resume.role1 = resume.role_two
        resume.role_description1 = resume.role_description_two
        resume.start_date_coach1 = resume.start_date
        resume.end_date_coach1  = resume.end_date
        resume.work_currently1 = resume.currently_two
        resume.location_coach1 = resume.currently_two

        resume.school_name = resume.school_name_one
        resume.start_date_school = resume.start_date_school
        resume.end_date_school = resume.end_date_graduation
        resume.school_currently = resume.currently_three

        resume.school_name1 = resume.school_name_two
        resume.degree_description1 = resume.degree_description_two
        resume.start_date_school1 = resume.end_date_two
        resume.end_date_school1 = resume.end_date_graduation
        resume.school_currently1 = resume.currently_four
        resume.location_school1 = resume.location_school_two

        resume.other_skills = resume.skills_one
        resume.other_skills1 = resume.skills_two
        resume.other_skills2 = resume.skills_three
        resume.other_skills3 = resume.skills_four
        resume.other_skills4 = resume.skills_five
        resume.other_skills5 = resume.skills_six

        db.session.add(resume)
        db.session.commit()


if __name__ == '__main__':
    app.run()
