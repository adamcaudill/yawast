FROM python:3.7-stretch

RUN apt-get update && apt-get install -y \
	apt-transport-https \
	ca-certificates \
	curl \
	wget \
	gnupg \
	unzip \
    --no-install-recommends \
	&& curl -sSL https://dl.google.com/linux/linux_signing_key.pub | apt-key add - \
	&& echo "deb https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
	&& apt-get update && apt-get install -y google-chrome-stable \
    fontconfig \
    fonts-ipafont-gothic \
    fonts-wqy-zenhei \
    fonts-thai-tlwg \
    fonts-kacst \
    fonts-noto \
    ttf-freefont \
    --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN CHROME_STRING=$(/usr/bin/google-chrome-stable --version) \
  && CHROME_VERSION_STRING=$(echo "${CHROME_STRING}" | grep -oP "\d+\.\d+\.\d+\.\d+") \
  && CHROME_MAJOR_VERSION=$(echo "${CHROME_VERSION_STRING%%.*}") \
  && wget --no-verbose -O /tmp/LATEST_RELEASE "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_${CHROME_MAJOR_VERSION}" \
  && CD_VERSION=$(cat "/tmp/LATEST_RELEASE") \
  && rm /tmp/LATEST_RELEASE \
  && CHROME_DRIVER_VERSION="${CD_VERSION}" \
  && echo "Using chromedriver version: "$CD_VERSION \
  && echo "Using Chrome version:       "$CHROME_VERSION_STRING \
  && wget --no-verbose -O /tmp/chromedriver_linux64.zip https://chromedriver.storage.googleapis.com/$CD_VERSION/chromedriver_linux64.zip \
  && unzip /tmp/chromedriver_linux64.zip -d /usr/bin/ \
  && rm /tmp/chromedriver_linux64.zip \
  && chmod +x /usr/bin/chromedriver

COPY . /data
WORKDIR /data

ENV LANG      C.UTF-8
ENV LANGUAGE  C.UTF-8
ENV LC_ALL    C.UTF-8

RUN pip install -r requirements.txt

RUN cd /data/ && python -m unittest discover

ENTRYPOINT ["/data/bin/yawast"]
