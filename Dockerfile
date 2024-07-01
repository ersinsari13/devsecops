FROM adoptopenjdk/openjdk8:alpine-slim
EXPOSE 8080
COPY target/petclinic.war petclinic.war
RUN addgroup --system devops-security && adduser --uid 999 --system --ingroup devops-security devsecops
USER 999
ENTRYPOINT ["java", "-jar", "/home/devsecops/petclinic.war"]