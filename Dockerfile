# ─────────────────────────────────────────────────────────────────────────────
#  Multi-stage build
#
#  Stage 1 — build:   Maven + JDK 17 → produces the fat JAR
#  Stage 2 — runtime: slim JRE 17 Alpine → runs the JAR as a non-root user
#
#  Layer-caching trick: copy pom.xml and resolve dependencies BEFORE copying
#  source code, so the dependency layer is only rebuilt when pom.xml changes.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /app

# 1. Copy only the POM first — maximises Docker layer cache reuse
COPY pom.xml .
RUN mvn dependency:go-offline -q

# 2. Copy source and build (skip tests — they run in CI)
COPY src ./src
RUN mvn package -DskipTests -q

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Security: run as a dedicated non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the fat JAR from the build stage
COPY --from=build /app/target/*.jar app.jar

# Own the file as the non-root user
RUN chown appuser:appgroup app.jar

USER appuser

EXPOSE 8080

# Tune JVM for containers: respect cgroup memory/CPU limits
ENTRYPOINT ["java", \
            "-XX:+UseContainerSupport", \
            "-XX:MaxRAMPercentage=75.0", \
            "-jar", "app.jar"]
