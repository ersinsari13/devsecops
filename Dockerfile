FROM doptopenjdk/openjdk8:alpine-slim
EXPOSE 8082
ADD target/petclinic.war petclinic.war
ENTRYPOINT ["java","-jar","/petclinic.war"]