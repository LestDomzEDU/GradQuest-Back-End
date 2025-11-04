# use OpenJDK 17 slim base image
FROM openjdk:17-jdk-slim

# set working directory
WORKDIR /app

# copy Gradle wrapper and build files first for better layer caching
COPY gradlew ./
COPY gradle ./gradle
COPY build.gradle ./
COPY settings.gradle ./

# make gradlew executable
RUN chmod +x ./gradlew

# copy source code
COPY src ./src

# build the application inside the image (skip tests for faster builds)
RUN ./gradlew build -x test

# copy the runnable JAR (exclude *-plain.jar) to a consistent path
RUN find build/libs -name "*.jar" -not -name "*-plain.jar" -exec cp {} app.jar \;

# expose the application port we are using
EXPOSE 8080

# run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
