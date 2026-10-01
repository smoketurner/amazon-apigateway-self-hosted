# Builds the VTL oracle: Apache Velocity 1.7 and Jayway JsonPath 2.9.0 on a pinned JDK.
# Every jar is fetched by Maven coordinate and verified against a SHA-256 before use.
FROM eclipse-temurin@sha256:4d06038800655fe1211760cd561de70ef2ed7a47f5d69255e9834414602b7026

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN mkdir -p /opt/lib /opt/classes && cd /opt/lib \
    && while read -r sha path; do \
         curl -fsSLO "https://repo1.maven.org/maven2/${path}"; \
         echo "${sha}  $(basename "${path}")" | sha256sum --check --strict -; \
       done <<'JARS'
ec92dae810034f4b46dbb16ef4364a4013b0efb24a8c5dd67435cae46a290d8e org/apache/velocity/velocity/1.7/velocity-1.7.jar
87363a4c94eaabeefd8b930cb059f66b64c9f7d632862f23de3012da7660047b commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar
2c73b940c91250bc98346926270f13a6a10bb6e29d2c9316a70d134e382c873e commons-lang/commons-lang/2.4/commons-lang-2.4.jar
11a9ee6f88bb31f1450108d1cf6441377dec84aca075eb6bb2343be157575bea com/jayway/jsonpath/json-path/2.9.0/json-path-2.9.0.jar
432b9e545848c4141b80717b26e367f83bf33f19250a228ce75da6e967da2bc7 net/minidev/json-smart/2.5.0/json-smart-2.5.0.jar
12314fc6881d66a413fd66370787adba16e504fbf7e138690b0f3952e3fbd321 net/minidev/accessors-smart/2.5.0/accessors-smart-2.5.0.jar
1263369b59e29c943918de11d6d6152e2ec6085ce63e5710516f8c67d368e4bc org/ow2/asm/asm/9.3/asm-9.3.jar
ce0e71d673acb9036bb55d0244b261cf033f8e4c1245f14f931dfb1937dd4c95 org/slf4j/slf4j-api/2.0.11/slf4j-api-2.0.11.jar
JARS

COPY VtlOracle.java /src/VtlOracle.java
RUN javac -cp "/opt/lib/*" -d /opt/classes /src/VtlOracle.java

ENTRYPOINT ["java", "-Dfile.encoding=UTF-8", "-cp", "/opt/classes:/opt/lib/*", "VtlOracle"]
