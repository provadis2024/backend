import logging

from flask import Flask, request, jsonify
from flask_restful import Api, Resource, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, date
from sqlalchemy.exc import NoResultFound
from sqlalchemy import or_, and_, func, case, literal
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zeiterfassung.sqlite3'
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Configure JWT
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)  # Token expiration time
app.config['JWT_TOKEN_LOCATION'] = ['headers']

# define the database models
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    user_password = db.Column(db.String(120), nullable=False)
    user_role = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.user_password = generate_password_hash(password)

class Project(db.Model):
    project_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(400))

class User_project(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), primary_key=True, nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.project_id'), primary_key=True, nullable=False)

class Task(db.Model):
    task_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.project_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(400))

class Time_entry(db.Model):
    time_entry_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.task_id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.project_id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime)

# create the API resources for each endpoint
class Home(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        return {'message': f'Hello, {user.username}! Welcome to the Time Management System'}, 201

class SignIn(Resource):
    def post(self):
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return {'message': 'Missing username or password'}, 400

            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.user_password, password):
                access_token = create_access_token(identity=user.user_id)
                return {
                    'message': 'Signed in successfully',
                    'access_token': access_token,
                    'user_id': user.user_id,
                    'username': user.username,
                    'user_role': user.user_role
                }, 200
            else:
                return {'message': 'Invalid credentials'}, 401
        except Exception as e:
            return {'message': 'Error signing in. Incorrect username or password'}, 500


class Projects(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        try:
            query = Project.query

            if user.user_role == "project_manager":
                query = query.filter(Project.owner_id == user.user_id)
            if user.user_role == "employee":
                query = query.outerjoin(User_project).filter(
                    or_(
                        Project.owner_id == user.user_id,
                        and_(User_project.user_id == user.user_id, User_project.project_id == Project.project_id)
                    )
                ).distinct()

            projects = query.all()
            if not projects:
                return {'message': 'No projects available'}, 201
            return jsonify([{
                'project_id': p.project_id,
                'owner_id': p.owner_id,
                'name': p.name,
                'description': p.description
            } for p in projects])
        except Exception as e:
            return {'message':f'Error: {str(e)}'},500

    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        data = request.get_json()

        if user.user_role == "project_manager" or user.user_role == "admin":
            try:
                new_project = Project(
                    name=data['name'],
                    owner_id=data['owner_id'],
                    description=data['description']
                    if 'description' in data else None)

                db.session.add(new_project)
                db.session.commit()

                if 'user_id' in data:
                    new_user_project = User_project(
                        project_id=new_project.project_id,
                        user_id=data.get('user_id')
                    )
                    db.session.add(new_user_project)
                    db.session.commit()

                return {'message': 'Project created successfully', 'project_id': new_project.project_id}, 201
            except Exception as e:
                db.session.rollback()
                return {'message':f'Error creating a project: {str(e)}'},500

        else:
            return {'message': 'Only project managers and admins are allowed to create projects'}, 401

    @jwt_required()
    def put(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        data = request.get_json()

        if user.user_role == "project_manager" or user.user_role == "admin":
            if 'project_id' not in data:
                return {'message': 'Missing required data field: project_id'}, 400

            try:                                              # need to add description!!!
                if 'owner_id' in data:
                    project = Project.query.get_or_404(data['project_id'])
                    project.owner_id = data['owner_id']
                if 'user_id' in data:
                    new_user_project = User_project(
                        project_id=data.get('project_id'),
                        user_id=data.get('user_id')
                    )

                    db.session.add(new_user_project)
                db.session.commit()
                return {'message': 'Project data successfully changed'}, 201

            except Exception as e:
                db.session.rollback()
                return {'message':f'Error updating project: {str(e)}'},500

        else:
            return {'message': 'Only project managers and admins are allowed to edit projects'}, 401

class Users(Resource):
    def get(self):
        try:
            users = User.query.all()
            if not users:
                return {'message': 'No users available'}, 201
            return jsonify([{
                'user_id': u.user_id,
                'username': u.username,
                'user_role': u.user_role
            } for u in users])
        except Exception as e:
            return {'message':f'Error: {str(e)}'},500

    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        data = request.get_json()

        if user.user_role == "admin":
            try:
                user = User.query.filter_by(username=data['username']).first()
                if user:
                    return {'message': 'This username already exists. Choose another name.'}, 401
                else:
                    new_user = User(username=data['username'],
                                    user_role=data['user_role'])
                    new_user.set_password(data['password'])
                    db.session.add(new_user)
                    db.session.commit()
                    return {'message': 'User created successfully',
                            'user_id': new_user.user_id}, 201
            except Exception as e:
                db.session.rollback()
                return {'message':f'Error creating a user: {str(e)}'},500
        else:
            return {'message': 'Only admins are allowed to create new users'}, 401

    @jwt_required()
    def put(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        data = request.get_json()

        if user.user_role == "admin":
            try:
                if "user_id" not in data:
                    return {'message': 'Error changing user'}, 500
                user = User.query.get(data['user_id'])
                if user:
                    if "password" in data:
                        user.password = set_password(user, data['password'])
                    if "user_role" in data:
                        user.user_role = data['user_role']
                    if "username" in data:
                        user.username = data['username']
                    db.session.commit()
                    return {'message': 'The user data was successfully changed'}, 201
                else:
                    return {'message': 'The user does not exist'}, 201
            except Exception as e:
                db.session.rollback()
                return {'message': f'Error changing user: {str(e)}'}, 500

        try:
            if "password" in data:
                user.password = data['password']
            if "username" in data:
                user.username = data['username']

            db.session.commit()
            return {'message':'The user data was successfully changed'},201
        except Exception as e:
            db.session.rollback()
            return {'message':f'Error changing user: {str(e)}'},500

class Tasks(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            abort(404, message="User not found")

        try:
            is_admin = user.user_role == 'admin'

            if is_admin:
                tasks = Task.query.all()
            else:
                tasks = Task.query.join(Project).join(User_project).filter(
                    or_(
                        Project.owner_id == current_user_id,
                        User_project.user_id == current_user_id
                    )
                ).all()

            return jsonify([{
                'task_id': task.task_id,
                'name': task.name,
                'description': task.description,
                'project_id': task.project_id
            } for task in tasks])
        except Exception as e:
            return {'message': f'Error: {str(e)}'},500

    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        data = request.get_json()

        if "project_id" not in data:
            abort(404, message="Missing project id")
        try:
            if user.user_role == "admin":
                new_task = Task(
                    name=data['name'],
                    description=data.get('description') if 'description' in data else None,
                    project_id=data['project_id'])
                db.session.add(new_task)
                db.session.commit()
                return {'message': 'Task created successfully', 'task_id': new_task.task_id}, 201

            if user.user_role == "project_manager":
                project = Project.query.get(data['project_id'])
                if not project:
                    abort(404, message="Project not found")

                # Check if the user is the owner of the project
                if project.owner_id != current_user_id:
                    return {'message': 'Unauthorized to create task in this project'}, 403

                new_task = Task(
                    name=data['name'],
                    description=data.get('description'),
                    project_id=data['project_id']
                )
                db.session.add(new_task)
                db.session.commit()

                return {
                    'message': 'Task created successfully',
                    'task_id': new_task.task_id
                }, 201
            else:
                return {'message': 'Only admin and project manager can create tasks'}, 403

        except Exception as e:
            db.session.rollback()
            return {'message':f'Error creating a task: {str(e)}'},500

class Booking(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        data = request.get_json()

        if 'start_time' not in data or 'project_id' not in data or 'user_id' not in data or 'task_id' not in data:
            msg = 'Missing required field(s):'
            if 'start_time' not in data:
                msg += ' start_time'
            if 'project_id' not in data:
                msg += ' project_id'
            if 'user_id' not in data:
                msg += ' user_id'
            if 'task_id' not in data:
                msg += ' task_id'

        if msg:
            return {'message': msg}, 400

        if user.user_role != "admin":
            if CheckTime(data['start_time']) == False:
                return {'message': 'The time entry cannot be older than one week or be in the future'}, 400

            if 'end_time' in data:
                if CheckTime(data['end_time']) == False:
                    return {'message': 'The time entry cannot be older than one week or be in the future'}, 400

        try:
            # Create a new time entry
            new_time_entry = Time_entry(
                start_time=datetime.fromisoformat(data['start_time']),
                user_id=user.user_id,
                project_id=data.get('project_id'),
                task_id=data.get('task_id'),
                end_time=datetime.fromisoformat(data['end_time']) if 'end_time' in data else None
            )

            # Add to database and commit
            db.session.add(new_time_entry)
            db.session.commit()

            return {
                'message': 'Time entry booked successfully',
                'time_entry_id': new_time_entry.time_entry_id
            }, 201

        except Exception as e:
            db.session.rollback()
            return {'message': f'Error creating time entry: {str(e)}'}, 500

    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        time_entries = Time_entry.query.all()

        if not time_entries:
            return {'message': 'No time entries available'}, 201

        if user.user_role == "admin":
            try:
                time_entries = Time_entry.query.all()

                return jsonify([{
                    'time_entry_id': te.time_entry_id,
                    'user_id': te.user_id if te.user_id else None,
                    'task_id': te.task_id if te.task_id else None,
                    'project_id': te.project_id if te.project_id else None,
                    'start_time': te.start_time.isoformat(" ", "minutes"),
                    'end_time': te.end_time.isoformat() if te.end_time else None
                } for te in time_entries])
            except Exception as e:
                return {'message':f'Error: {str(e)}'},500

        if user.user_role == "project_manager":
            try:
                query = Time_entry.query
                time_entries = query.outerjoin(Project).filter(
                    or_(
                        Project.owner_id == user.user_id,
                        and_(Project.owner_id == user.user_id,
                             Project.project_id == Time_entry.project_id)
                    )
                ).distinct()
                return jsonify([{
                    'time_entry_id': te.time_entry_id,
                    'user_id': te.user_id if te.user_id else None,
                    'task_id': te.task_id if te.task_id else None,
                    'project_id': te.project_id if te.project_id else None,
                    'start_time': te.start_time.isoformat(" ", "minutes"),
                    'end_time': te.end_time.isoformat() if te.end_time else None
                } for te in time_entries])
            except Exception as e:
                return {'message':f'Error: {str(e)}'},500
        if user.user_role == "employee":
            try:
                query = Time_entry.query
                time_entries = query.filter(Time_entry.user_id == user.user_id)
                return jsonify([{
                    'time_entry_id': te.time_entry_id,
                    'user_id': te.user_id,
                    'task_id': te.task_id if te.task_id else None,
                    'project_id': te.project_id if te.project_id else None,
                    'start_time': te.start_time.isoformat(" ", "minutes"),
                    'end_time': te.end_time.isoformat() if te.end_time else None
                } for te in time_entries])
            except Exception as e:
                return {'message': f'Error: {str(e)}'}, 500

    @jwt_required()
    def put(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        data = request.get_json()

        if 'time_entry_id' not in data:
            return {'message': 'Missing required field: time_entry_id'}, 400

        if user.user_role != "admin":
            if CheckTime(data['start_time']) == False:
                return {'message': 'The time entry cannot be older than one week or be in the future'}, 400

            if 'end_time' in data:
                if CheckTime(data['end_time']) == False:
                    return {'message': 'The time entry cannot be older than one week or be in the future'}, 400

        try:
            time_entry = Time_entry.query.get_or_404(data['time_entry_id'])
            if 'start_time' in data:
                time_entry.start_time = datetime.fromisoformat(data['start_time'])
            if 'project_id' in data:
                time_entry.project_id = data['project_id']
            if 'task_id' in data:
                time_entry.task_id = data['task_id']
            if 'end_time' in data:
                time_entry.end_time = datetime.fromisoformat(data['end_time'])

            db.session.commit()
            return {'message': 'Time entry updated successfully'}, 200
        except NoResultFound:
            return {'message': 'Time entry not found'}, 404
        except Exception as e:
            db.session.rollback()
            return {'message': f'Error updating time entry: {str(e)}'}, 500

class TimeEntries(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if user.user_role == "employee":
            return {'message': 'Unauthorized access'}, 403

        user_id = request.args.get('user_id')
        task_id = request.args.get('task_id')
        project_id = request.args.get('project_id')

        try:
            query = Time_entry.query
            if user_id:
                query = query.filter(Time_entry.user_id == user_id)

            if task_id:
                query = query.filter(Time_entry.task_id == task_id)
            if project_id:
                query = query.filter(Time_entry.project_id == project_id)

            time_entries = query.all()
            if not time_entries:
                return {'message': 'No time entries available'}, 201
            return jsonify([{
                'time_entry_id': te.time_entry_id,
                'user_id': te.user_id if te.user_id else None,
                'task_id': te.task_id if te.task_id else None,
                'project_id': te.project_id if te.project_id else None,
                'start_time': te.start_time.isoformat(),
                'end_time': te.end_time.isoformat() if te.end_time else None
            } for te in time_entries])
        except Exception as e:
            db.session.rollback()
            return {'message':f'Error creating time entry: {str(e)}'},500

    def post(self):
        data = request.get_json()

        try:
            new_time_entry = Time_entry(
                user_id=data['user_id'] if data.get('user_id') else None,
                task_id=data['task_id'] if data.get('task_id') else None,
                project_id=data['project_id'] if data.get('project_id') else None,
                start_time=datetime.fromisoformat(data['start_time']),
                end_time=datetime.fromisoformat(data['end_time']) if data.get('end_time') else None
            )
            db.session.add(new_time_entry)
            db.session.commit()
            return {'message': 'Time entry created successfully', 'time_entry_id': new_time_entry.time_entry_id}, 201
        except Exception as e:
            db.session.rollback()
            return {'message':f'Error updating the time entry: {str(e)}'},500

class UserResource(Resource):
    @jwt_required()
    def get(self, user_id):
        current_user_id = get_jwt_identity()
        if current_user_id != user_id:
            return {'message': 'Unauthorized access'}, 403

        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404

        query = Project.query
        projects = query.join(User_project).filter(User_project.user_id == user_id).all()

        return {
            'user_id': user.user_id,
            'username': user.username,
            'user_role': user.user_role,
            'projects': [{
                'name': project.name,
                'project_id': project.project_id
            } for project in projects]
        }

class ProjectResource(Resource):
    @jwt_required()
    def get(self, project_id):
        current_user_id = get_jwt_identity()
        project = Project.query.get(project_id)
        user = User.query.get(current_user_id)

        if not project:
            abort(404, message="Project not found")

        if current_user_id != project.owner_id and user.user_role != "admin":
            return {'message': 'Unauthorized access'}, 403

        query = User.query
        users = query.join(User_project).filter(User_project.project_id == project_id).all()

        response = {
            'project_id': project.project_id,
            'name': project.name,
            'description': project.description if project.description else None,
            'project_owner': project.owner_id,
            'users': [{
                'user_id': user.user_id,
                'username': user.username
            } for user in users]
        }

        return jsonify(response)

class UserWorkHoursResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if user.user_role != 'admin':
            return {'message': 'Unauthorized access'}, 403

        # Get date range parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # Convert string dates to datetime objects
        try:
            if start_date:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
            else:
                start_date = datetime.min

            if end_date:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = end_date + timedelta(days=1)
            else:
                end_date = datetime.utcnow()
        except ValueError:
            return {'message': 'Invalid date format. Use YYYY-MM-DD.'}, 400

        # Check if there are any time entries in the specified date range
        time_entries_count = Time_entry.query.filter(
            and_(
                Time_entry.start_time >= start_date,
                Time_entry.start_time < end_date
            )
        ).count()

        logging.info(f"Number of time entries in date range: {time_entries_count}")

        if time_entries_count == 0:
            return {'message': 'No time entries found in the specified date range'}, 404

        # Simplified query
        query = db.session.query(
            Time_entry.user_id,
            func.sum(
                case(
                    (Time_entry.end_time != None,
                     (func.julianday(func.min(Time_entry.end_time, end_date)) -
                      func.julianday(Time_entry.start_time)) * 24),
                    else_=(func.julianday(end_date) -
                           func.julianday(Time_entry.start_time)) * 24
                )
            ).label('total_hours_worked')
        ).filter(
            and_(
                Time_entry.start_time >= start_date,
                Time_entry.start_time < end_date
            )
        ).group_by(Time_entry.user_id)

        # Log the SQL query
        logging.info(f"SQL Query: {query}")

        results = query.all()

        logging.info(f"Query results: {results}")

        work_hours = [{'user_id': result.user_id, 'total_hours_worked': round(float(result.total_hours_worked), 2)} for
                      result in results]

        response = {
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'work_hours': work_hours
        }

        return jsonify(response)

class ProjectWorkHoursResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if user.user_role == 'employee':
            return {'message': 'Unauthorized access'}, 403

        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        try:
            if start_date:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
            else:
                start_date = datetime.min

            if end_date:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = end_date + timedelta(days=1)
            else:
                end_date = datetime.utcnow()
        except ValueError:
            return {'message': 'Invalid date format. Use YYYY-MM-DD.'}, 400

        time_entries_count = Time_entry.query.filter(
            and_(
                Time_entry.start_time >= start_date,
                Time_entry.start_time < end_date
            )
        ).count()

        logging.info(f"Number of time entries in date range: {time_entries_count}")

        if time_entries_count == 0:
            return {'message': 'No time entries found in the specified date range'}, 404

        if user.user_role == 'project_manager':
            owned_projects = db.session.query(Project.project_id).filter_by(owner_id=current_user_id).subquery()

            query = db.session.query(
                Time_entry.project_id,
                func.sum(
                    case(
                        (Time_entry.end_time != None,
                         (func.julianday(func.min(Time_entry.end_time, end_date)) -
                          func.julianday(Time_entry.start_time)) * 24),
                        else_=(func.julianday(end_date) -
                               func.julianday(Time_entry.start_time)) * 24
                    )
                ).label('total_hours_worked')
            ).filter(
                and_(
                    Time_entry.start_time >= start_date,
                    Time_entry.start_time < end_date,
                    Time_entry.project_id.in_(owned_projects)
                )
            ).group_by(Time_entry.project_id)
        else:
            query = db.session.query(
                Time_entry.project_id,
                func.sum(
                    case(
                        (Time_entry.end_time != None,
                         (func.julianday(func.min(Time_entry.end_time, end_date)) -
                          func.julianday(Time_entry.start_time)) * 24),
                        else_=(func.julianday(end_date) -
                               func.julianday(Time_entry.start_time)) * 24
                    )
                ).label('total_hours_worked')
            ).filter(
                and_(
                    Time_entry.start_time >= start_date,
                    Time_entry.start_time < end_date
                )
            ).group_by(Time_entry.project_id)

        logging.info(f"SQL Query: {query}")

        results = query.all()

        logging.info(f"Query results: {results}")

        work_hours = [{'project_id': result.project_id,
                       'total_hours_worked_on_project': round(float(result.total_hours_worked), 2)} for
                      result in results]

        response = {
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'work_hours': work_hours
        }

        return jsonify(response)

class TaskWorkHoursResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return {'message': 'User not found'}, 404

        if user.user_role == 'employee':
            return {'message': 'Unauthorized access'}, 403

        # Get date range parameters (optional)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        try:
            if start_date:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
            else:
                start_date = datetime.min

            if end_date:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
                end_date = end_date + timedelta(days=1)
            else:
                end_date = datetime.utcnow()
        except ValueError:
            return {'message': 'Invalid date format. Use YYYY-MM-DD.'}, 400

        # Base query for time spent on tasks
        time_query = db.session.query(
            Time_entry.task_id,
            func.sum(
                case(
                    (Time_entry.end_time != None,
                     (func.julianday(func.min(Time_entry.end_time, end_date)) -
                      func.julianday(func.max(Time_entry.start_time, start_date))) * 24),
                    else_=(func.julianday(end_date) -
                           func.julianday(func.max(Time_entry.start_time, start_date))) * 24
                )
            ).label('total_hours')
        ).filter(
            and_(
                Time_entry.start_time < end_date,
                or_(Time_entry.end_time == None, Time_entry.end_time > start_date)
            )
        ).group_by(Time_entry.task_id).subquery()

        # Query for projects
        if user.user_role == 'project_manager':
            projects = Project.query.filter_by(owner_id=current_user_id).all()
        else:  # admin
            projects = Project.query.all()

        projects_data = []
        for project in projects:
            # Query tasks for each project
            tasks = Task.query.filter_by(project_id=project.project_id).all()
            tasks_data = []
            for task in tasks:
                task_time = db.session.query(time_query.c.total_hours).filter(
                    time_query.c.task_id == task.task_id).scalar() or 0
                tasks_data.append({
                    'task_id': task.task_id,
                    'task_name': task.name,
                    'time_spent': round(float(task_time), 2)
                })

            projects_data.append({
                'project_id': project.project_id,
                'project_name': project.name,
                'tasks': tasks_data
            })

        response_data = {
            'date_range': {
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': (end_date - timedelta(days=1)).strftime('%Y-%m-%d')
            },
            'projects': projects_data
        }

        return jsonify(response_data)

# set up the API routes
api.add_resource(Home, '/')
api.add_resource(SignIn, '/signin')
api.add_resource(Projects, '/projects')
api.add_resource(Users, '/users')
api.add_resource(Tasks, '/tasks')
api.add_resource(Booking, '/booking')
api.add_resource(TimeEntries, '/time_entries')
api.add_resource(UserResource, '/users/<int:user_id>')
api.add_resource(ProjectResource, '/projects/<int:project_id>')
api.add_resource(UserWorkHoursResource, '/user_work_hours')
api.add_resource(ProjectWorkHoursResource, '/project_work_hours')
api.add_resource(TaskWorkHoursResource, '/task_work_hours')

# initialize the database
with app.app_context():
    db.create_all()

def CheckTime(entry):
    date = ((datetime.fromisoformat(entry)))
    today = datetime.fromisoformat(datetime.now().strftime("%Y-%m-%d %H:%M"))
    if (today - date > timedelta(days=7) or today < date):
        return False

def set_password(self, password):
    self.user_password = generate_password_hash(password)

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0")
