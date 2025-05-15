# TODO-App
A comprehensive To Do List App built with Django that allows users to create, organize, and track their tasks. The application features user authentication, task CRUD operations, and a clean, responsive interface.
## 🔧 Features
### Core Functionality
- User Authentication: Register, login, logout, and profile management
- Task Management: Create, read, update, and delete tasks
- Set due dates 
- Task Statuses: To Do, In Progress, Done
### Technical Features
- Django REST Framework for API endpoints
- JWT Authentication
- Bootstrap 5 for styling
- Custom template tags and filters
- Comprehensive error handling
## 🛠 Setup Instructions
1. Clone the repository
```bash
git clone https://github.com/Makihataima-Ken/Auth-Register-Django.git
```
2. Create and activate a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install dependencies
```bash
pip install -r requirements.txt
```
4. Migrate database
```bash
python manage.py migrate
```
5. Run the server
```bash
python manage.py runserver
```
## URL Structure
### Authentication URLs
- ```/login/``` - User login
- ```/logout/``` - User logout
- ```/register/``` - New user registration
- ```/profile/``` - User profile
### Task URLs
- ```tasks/```- List User's Tasks
- ```'tasks/<int:pk>/```- Task detail view
- ```tasks/create/```- Create new task
- ```tasks/update/<int:pk>/```- Update task
- ```'tasks/delete/<int:pk>/```- Delete task
## Templates
- The application uses Django's template system with Bootstrap 5 for styling. Key templates:
### Task Templates
- task_list.html - Displays all tasks
- task_detail.html - Detailed task view
- task_form.html - Create/update form
- task_confirm_delete.html - Delete confirmation
### Authentication Templates
- login.html - Login form
- register.html - Registration form
- profile.html - User profile