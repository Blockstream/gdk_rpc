FROM debian:buster@sha256:903779f30a7ee46937bfb21406f125d5fdace4178074e1cc71c49039ebf7f48f
COPY buster_deps.sh /deps.sh
RUN /deps.sh && rm /deps.sh
