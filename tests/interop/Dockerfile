# Builds the CDOC2 reference CLI so umbrik can be round-tripped against it.
#
# Both repositories are pinned to commits, not branches: an interop job that silently follows
# upstream cannot distinguish "umbrik regressed" from "upstream changed".
# Pinned by digest, like the repositories below: an interop job that silently follows a
# moving base image cannot distinguish "umbrik regressed" from "the image changed".
FROM maven:3.9-eclipse-temurin-21@sha256:8f6ac126f7810bb5549c4cd122d2bf0e9cda5bdeb0838aa928f09e779fd8bef8 AS build

ARG OPENAPI_REPO=https://github.com/open-eid/cdoc2-openapi.git
ARG OPENAPI_REF=6dc1694261214d0e9ccf30de93e942e8e6291568
ARG AUTH_REPO=https://github.com/open-eid/cdoc2-auth.git
# `develop`, pinned by SHA: this is where cdoc2-auth-token 0.7.2 lives. `master` is still on
# 0.3.3, and cdoc2-lib requires 0.7.2.
ARG AUTH_REF=ccc576a83fcf3e5a13667609b95a7d5e9915ad6f
ARG CDOC2_REPO=https://github.com/open-eid/cdoc2-java-ref-impl.git
ARG CDOC2_REF=daff207f719b4c1cfc4a1138733a4f8c531524c6

# cdoc2-client resolves `ee.cyber.cdoc2.openapi:cdoc2-key-capsules-openapi:yaml`, which is
# published to GitHub Packages rather than Maven Central. Rather than requiring a token, build
# it from source: the repo's `install-file` executions put it in the local repository under the
# version declared inside the YAML itself.
WORKDIR /build
RUN git clone "${OPENAPI_REPO}" openapi \
 && cd openapi \
 && git checkout "${OPENAPI_REF}" \
 && mvn -q -B install

# cdoc2-lib compiles against ee.cyber.cdoc2:cdoc2-auth-token, also GitHub Packages only.
RUN git clone "${AUTH_REPO}" auth \
 && cd auth \
 && git checkout "${AUTH_REF}" \
 && mvn -q -B install -DskipTests -Dmaven.javadoc.skip=true \
      -Dcheckstyle.skip=true -Dspotbugs.skip=true

RUN git clone "${CDOC2_REPO}" repo \
 && cd repo \
 && git checkout "${CDOC2_REF}"

WORKDIR /build/repo
# The schema module invokes an x86_64 flatc binary, so this image must be built for
# linux/amd64 (see tests/interop/README.md).
RUN mvn -q -B -pl cdoc2-cli -am package \
      -DskipTests -Dmaven.javadoc.skip=true \
      -Dcheckstyle.skip=true -Dspotbugs.skip=true \
 && cp cdoc2-cli/target/cdoc2-cli-*.jar /build/cdoc2-cli.jar

FROM eclipse-temurin:21-jre@sha256:7a65df4b22d2de92d4e04056e884f3b9122d70b21e2847fd66084278bd0ce037
COPY --from=build /build/cdoc2-cli.jar /opt/cdoc2-cli.jar
# Long filenames and Estonian characters must survive the round trip.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENTRYPOINT ["java", "-Dee.cyber.cdoc2.overwrite=true", "-jar", "/opt/cdoc2-cli.jar"]
