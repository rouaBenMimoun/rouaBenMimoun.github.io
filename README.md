# rouaBenMimoun.github.io
Jakarta EE Web Application Project

This project is a Jakarta EE-based web application that includes two primary components:

An Identity and Access Management (IAM) server implemented using OAuth 2.0 and JWT tokens.

A Steganography Application for encoding and decoding messages in images.

Features

Identity and Access Management (IAM) Server

OAuth 2.0 Authentication: Provides secure user authentication and authorization.

JWT Tokens: Issues JSON Web Tokens (JWT) for stateless and secure communication.

User Management: Includes user registration, login, and role-based access control.

Steganography Application

Message Encoding: Allows users to embed secret messages into images using a custom algorithm.

Message Decoding: Extracts and displays the hidden messages from the encoded images.

User Authentication: Secures access to the steganography features through the IAM server.

Technologies Used

Jakarta EE: Core framework for building the application.

OAuth 2.0: For secure user authentication and authorization.

JWT (JSON Web Tokens): For stateless session management.

Maven: Dependency management and project build tool.

IntelliJ IDEA: Integrated development environment.

Java Persistence API (JPA): For database interactions.

WildFly: Application server for running the Jakarta EE application.

TLS 1.3: Ensures secure communication.

MongoDB: NoSQL database for data storage.

Frontend: HTML, CSS, and JavaScript (optional frameworks like Bootstrap for styling).

Prerequisites

Java Development Kit (JDK) 17 or higher.

Apache Maven 3.8+.

WildFly Server 26.x or higher.

MongoDB instance configured for the IAM server.

Installation and Setup

Clone the Repository:

git clone https://github.com/rouaBenMimoun/rouaBenMimoun.github.io


Configure the Database:

Update the database connection details in the configuration file (e.g., application.properties or equivalent) to point to your MongoDB instance.

Configure WildFly with TLS 1.3:

Set up a TLS 1.3 certificate and configure WildFly to use it for secure communication.

Ensure the standalone.xml or domain.xml is updated with the correct HTTPS settings.

Build the Project:

mvn clean install

Deploy to WildFly:

Start your WildFly server.

Deploy the generated .war file located in the target/ directory.

Run the Application:

Access the application in your browser at https://localhost:8443/your-app-context.

Usage

IAM Server

Register a new user by navigating to /auth/register.

Obtain an access token by logging in at /auth/login.

Use the token to authenticate API requests to protected endpoints.

Steganography Application

Log in to the application using your IAM credentials.

Navigate to the Steganography section:

Upload an image and input the message to encode.

Download the encoded image.

To decode, upload an encoded image to extract the hidden message.

Contributing

We welcome contributions to enhance the project. To contribute:

Fork the repository.

Create a new branch for your feature or bug fix.

Submit a pull request with a detailed description of your changes.



Contact

For any questions or support, please contact:

Email: roua.benmimoun@supcom.tn
       ahmedaziz.ladhari@supcom.tn

