# Project 3 Backend

Spring Boot REST API backend for managing student preferences, schools, applications, and reminders.

## Running the Application

### Option 1: Using Gradle

#### Run the Application
```bash
./gradlew bootRun
```

The application will start on `http://localhost:8080`

#### Run Tests
```bash
./gradlew test
```

### Option 2: Using Docker

#### Build the Docker Image
```bash
docker build -t project3-backend .
```

#### Run the Docker Container
```bash
docker run -p 8080:8080 project3-backend
```

The application will be accessible at `http://localhost:8080`

#### Stop the Container
```bash
docker stop project3-backend
```

#### Remove the Container
```bash
docker rm project3-backend
```

## Configuration

### Application Properties

The application uses Spring profiles for configuration:

- **Default profile**: `application.properties` - Basic configuration (uses H2 for local dev)
- **Production profile**: `application-prod.properties` - Supabase PostgreSQL database configuration

The active profile is set to `prod` by default in `application.properties`:

```properties
spring.profiles.active=prod
```

## API Endpoints

### User Endpoints
- `POST /api/users` - Create a new user
- `GET /api/users` - Get all users
- `GET /api/users/{userId}` - Get user by ID
- `GET /api/users/{userId}/student-id` - Get student ID by user ID
- `GET /api/users/email/{email}/student-id` - Get student ID by email
- `GET /api/users/test/student-id` - Get/create a test student ID

### Student Preferences Endpoints
- `POST /api/preferences?studentId={id}` - Create or update student preferences
- `GET /api/preferences?studentId={id}` - Get student preferences
- `PUT /api/preferences?studentId={id}` - Update student preferences (partial update supported)
- `DELETE /api/preferences?studentId={id}` - Delete student preferences

### School Endpoints
- `GET /api/schools` - Get all schools
- `GET /api/schools/{schoolId}` - Get school by ID
- `POST /api/schools` - Create a new school
- `PUT /api/schools/{schoolId}` - Update a school (partial update supported)
- `DELETE /api/schools/{schoolId}` - Delete a school
- `POST /api/schools/search` - Search schools by criteria

### Application Endpoints
- `GET /api/applications` - Get all applications
- `GET /api/applications/{applicationId}` - Get application by ID
- `POST /api/applications` - Create a new application
- `PUT /api/applications/{applicationId}` - Update an application
- `DELETE /api/applications/{applicationId}` - Delete an application

### Reminder Endpoints
- `GET /api/reminders` - Get all reminders
- `GET /api/reminders/{reminderId}` - Get reminder by ID
- `POST /api/reminders` - Create a new reminder
- `PUT /api/reminders/{reminderId}` - Update a reminder
- `DELETE /api/reminders/{reminderId}` - Delete a reminder

## Project Structure

```
src/
├── main/
│   ├── java/com/project03/
│   │   ├── controller/     # REST controllers
│   │   ├── model/          # JPA entities
│   │   ├── repository/     # JPA repositories
│   │   └── Project03Application.java
│   └── resources/
│       ├── application.properties
│       └── application-prod.properties
└── test/
    └── java/com/project03/
```

## Troubleshooting

### Port Already in Use

If port 8080 is already in use, you can change it in `application.properties`:
```properties
server.port=8081
```
### Docker Build Issues

If you encounter issues building the Docker image:
- Ensure Docker is running
- Check that all required files are present (gradlew, build.gradle, src/)
- Review the Dockerfile for any path issues