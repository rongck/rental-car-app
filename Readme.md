## 📚 Project Assignment: Deploying a Flask Application with Docker, Gunicorn, Nginx, and Terraform

### Project Description

In this project, you are expected to deploy a car rental application built with Python Flask onto an AWS EC2 instance using **Docker**, **Gunicorn**, **Nginx**, and **Terraform**. Your solution should include the steps and components below:

1. **Flask Application:** A simple car rental platform developed with Python Flask. The platform allows users to view cars and rent them.
2. **Docker Compose:** The application must run as multiple independent services managed by Docker Compose. The services are:

   * **app**: Flask application running with Gunicorn
   * **mysql**: MySQL database
   * **nginx**: Nginx server acting as a reverse proxy for the application
3. **Nginx Configuration:** Nginx must be configured to route incoming internet requests to the Flask application. Optionally, Nginx can also be configured to support SSL certificates.

---

## Project Steps

### 1. Writing the Dockerfile

* You will create a `Dockerfile` to build the Docker image for your Flask application.
* The image should install dependencies, then start the app using Gunicorn.
* Your `Dockerfile` should include:

  * Using a Python 3.9 base image
  * Installing required dependencies
  * Running the Flask app using Gunicorn

**Example Dockerfile:**

```dockerfile
# Base image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8000 for Gunicorn
EXPOSE 8000

# Command to run the application using Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:8000", "wsgi:app"]
```

---

### 2. Docker Compose File

* Docker Compose will manage the following services: `mysql`, `app` (Flask + Gunicorn), and `nginx` (reverse proxy).
* Each service should be configured independently.

**Example docker-compose.yml:**

```yaml
version: '3'
services:
  app:
    build: .
    container_name: flask_app
    environment:
      - DB_HOST=mysql
      - DB_USER=root
      - DB_PASSWORD=rootpassword
      - DB_NAME=arac_kiralama
    depends_on:
      - mysql
    networks:
      - app-network
    ports:
      - "8000:8000"

  mysql:
    image: mysql:5.7
    container_name: mysql_container
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: arac_kiralama
    networks:
      - app-network
    ports:
      - "3306:3306"

  nginx:
    image: nginx:latest
    container_name: nginx_reverse_proxy
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    ports:
      - "80:80"
    depends_on:
      - app
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```

---

### 3. Nginx Configuration

* Nginx should receive requests and forward them to the Flask app running via Gunicorn.

**Example nginx.conf:**

```nginx
server {
    listen 80;
    server_name ${DOMAIN_NAME} www.${DOMAIN_NAME};

    location / {
        proxy_pass http://app:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

### 4. Deploying to EC2 with Terraform

* Terraform should create an EC2 instance on AWS and run Docker Compose on that instance.

**Example Terraform configuration:**

```hcl
provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "flask_app" {
  ami           = "ami-0c55b159cbfafe1f0" # A suitable EC2 AMI ID
  instance_type = "t2.micro"

  tags = {
    Name = "FlaskAppInstance"
  }

  user_data = <<-EOF
    #!/bin/bash
    apt update -y
    apt install -y docker.io
    apt install -y docker-compose
    cd /home/ubuntu
    git clone https://github.com/kullanici/arac-kiralama.git
    cd arac-kiralama
    docker-compose up -d
  EOF
}
```

---

## Assignment Requirements

1. **Create the Dockerfile and Docker Compose Files**

   * Write a Dockerfile so the Flask app can run in a container.
   * Configure MySQL, Nginx, and Flask services in `docker-compose.yml`.

2. **Run the Application**

   * Start the application using Docker Compose.
   * Verify that Nginx correctly proxies requests to the Flask application.

3. **Deploy to EC2 Using Terraform**

   * Launch an EC2 instance via Terraform and run Docker Compose on it.

4. **Push the Project to a Repository**

   * Upload all project files to a GitHub repository.
