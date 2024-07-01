FROM openjdk:8
EXPOSE 8082
COPY target/petclinic.war petclinic.war
RUN addgroup -S devops-security && adduser -u 999 -S devsecops -G devops-security
USER 999
ENTRYPOINT ["java","-jar","/home/devsecops/petclinic.war"]
