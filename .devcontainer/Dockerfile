FROM public.ecr.aws/ubuntu/ubuntu:24.04_stable

# Environment variable to configure timezone
ENV TZ=Etc/UTC

WORKDIR /tmp/workdir

RUN apt-get update \
    && apt-get install -y \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y \
    build-essential pkg-config g++ git cmake yasm \
    zlib1g-dev libfreetype6-dev libjpeg62-dev libpng-dev  \
    libmad0-dev libfaad-dev libogg-dev libvorbis-dev libtheora-dev  \
    liba52-0.7.4-dev libavcodec-dev libavformat-dev libavutil-dev  \
    libswscale-dev libavdevice-dev libnghttp2-dev libopenjp2-7-dev  \
    libcaca-dev libxv-dev x11proto-video-dev libgl1-mesa-dev  \
    libglu1-mesa-dev x11proto-gl-dev libxvidcore-dev libssl-dev  \
    libjack-jackd2-dev libasound2-dev libpulse-dev libsdl2-dev  \
    dvb-apps mesa-utils libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/gpac/deps_unix /tmp/gpac/deps_unix && \
    cd /tmp/gpac/deps_unix && \
    git submodule update --init --recursive --force --checkout && \
    ./build_all.sh linux  &&  \
    ldconfig
