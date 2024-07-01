FROM openjdk:8
EXPOSE 8082
RUN addgroup -S devops-security && adduser -u 999 -S devsecops -G devops-security
COPY target/petclinic.war petclinic.war
USER 999
ENTRYPOINT ["java","-jar","/home/devsecops/petclinic.war"]