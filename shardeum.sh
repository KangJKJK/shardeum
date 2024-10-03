#!/usr/bin/env bash

# 컬러 정의
export RED='\033[0;31m'
export YELLOW='\033[1;33m'
export GREEN='\033[0;32m'
export BOLD_RED='\033[1;31m'
export BOLD_YELLOW='\033[1;33m'
export BOLD_GREEN='\033[1;32m'
export NC='\033[0m'  # 색상 없음

set -e

echo -e "${GREEN}스크립트 작성자: https://t.me/kjkresearch${NC}"
read -p "샤르데움 노드설치를 시작합니다. 엔터를 눌러주세요"

# 환경/운영체제 가져오기
environment=$(uname)

# 오류 메시지와 함께 종료하는 함수
exit_with_error() {
    echo -e "${RED}오류: $1${NC}"
    exit 1
}

# 운영체제를 확인하고 프로세서 정보를 가져오기
case "$environment" in
    Linux)
        processor=$(uname -m)
        ;;
    Darwin)
        processor=$(uname -m)
        ;;
    *MINGW*)
        exit_with_error "$environment (Windows) 환경은 아직 지원되지 않습니다. WSL(WSL2 권장) 또는 Linux VM을 사용하세요. 설치 프로그램을 종료합니다."
        ;;
    *)
        processor="알 수 없음"
        ;;
esac

# ARM 프로세서 또는 알 수 없는 프로세서를 확인하고, 지원되지 않으면 종료
if [[ "$processor" == *"arm"* || "$processor" == "알 수 없음" ]]; then
    exit_with_error "$processor는 아직 지원되지 않습니다. 설치 프로그램을 종료합니다."
fi

# 감지된 환경과 프로세서를 출력
echo -e "${GREEN}$environment 환경에서 $processor가 발견되었습니다.${NC}"

# 해싱 명령이 있는지 확인
if ! (command -v openssl > /dev/null || command -v shasum > /dev/null || command -v sha256sum > /dev/null); then
  echo -e "${YELLOW}지원되는 해싱 명령을 찾을 수 없습니다.${NC}"
  read -p "openssl을 설치하시겠습니까? (y/n) " -n 1 -r
  echo

  if [[ $REPLY =~ ^[Yy]$ ]]; then
    # 패키지 관리자를 감지하고 openssl 설치
    if command -v apt-get > /dev/null; then
      sudo apt-get update && sudo apt-get install -y openssl
    elif command -v yum > /dev/null; then
      sudo yum install -y openssl
    elif command -v dnf > /dev/null; then
      sudo dnf install -y openssl
    else
      echo -e "${RED}지원되지 않는 패키지 관리자입니다. openssl을 수동으로 설치하세요.${NC}"
      exit 1
    fi
  else
    echo -e "${RED}openssl, shasum 또는 sha256sum을 설치하고 다시 시도하세요.${NC}"
    exit 1
  fi
fi

read -p "노드가 사용할 기본 디렉토리를 다음으로 설정합니다. 확인하시고 엔터를 눌러주세요: /root/.shardeum "

# 작업 디렉토리를 /root/.shardeum으로 고정
NODEHOME="/root/.shardeum"

# 최종 디렉토리 출력
echo "기본 디렉토리가 설정되었습니다: $NODEHOME"

# 이 스크립트가 성공하기 위해 필요한 모든 항목 확인 (docker 및 docker-compose 접근)
# 확인이 실패하면 누락된 종속성을 설치 시도
command -v git >/dev/null 2>&1 || {
    echo >&2 "'git'이 설치되어 있지 않습니다. git을 설치 시도 중..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y git
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y git
    else
        echo >&2 "git을 설치할 수 없습니다. 수동으로 설치하세요."
        exit 1
    fi
}

command -v docker >/dev/null 2>&1 || {
    echo >&2 "'docker'가 설치되어 있지 않습니다. docker를 설치 시도 중..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
}

if ! command -v docker-compose &>/dev/null && ! docker --help | grep -q "compose"; then
    echo "docker-compose 또는 docker compose가 설치되어 있지 않습니다. docker-compose를 설치 시도 중..."
    sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

# 설치 확인
command -v git >/dev/null 2>&1 || { echo >&2 "git 설치에 실패했습니다. 수동으로 설치하세요."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo >&2 "docker 설치에 실패했습니다. 수동으로 설치하세요."; exit 1; }
if command -v docker-compose &>/dev/null; then
    echo -e "${GREEN}docker-compose가 이 머신에 설치되었습니다.${NC}"
elif docker --help | grep -q "compose"; then
    echo -e "${GREEN}docker compose 서브커맨드가 이 머신에 설치되었습니다.${NC}"
else
    echo -e "${RED}docker-compose 설치에 실패했습니다. 수동으로 설치하세요.${NC}"
    exit 1
fi

export DOCKER_DEFAULT_PLATFORM=linux/amd64

docker-safe() {
  if ! command -v docker &>/dev/null; then
    echo -e "${RED}docker가 이 머신에 설치되어 있지 않습니다.${NC}"
    exit 1
  fi

  if ! docker $@; then
    echo -e "${YELLOW}sudo로 다시 시도 중...${NC}" >&2
    sudo docker $@
  fi
}

docker-compose-safe() {
  if command -v docker-compose &>/dev/null; then
    cmd="docker-compose"
  elif docker --help | grep -q "compose"; then
    cmd="docker compose"
  else
    echo -e "${RED}docker-compose 또는 docker compose가 이 머신에 설치되어 있지 않습니다.${NC}"
    exit 1
  fi

  if ! $cmd $@; then
    echo -e "${YELLOW}sudo로 다시 시도 중...${NC}"
    sudo $cmd $@
  fi
}

get_ip() {
  local ip
  if command -v ip >/dev/null; then
    ip=$(ip addr show $(ip route | awk '/default/ {print $5}') | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1)
  elif command -v netstat >/dev/null; then
    # 기본 경로 인터페이스 가져오기
    interface=$(netstat -rn | awk '/default/{print $4}' | head -n1)
    # 기본 인터페이스의 IP 주소 가져오기
    ip=$(ifconfig "$interface" | awk '/inet /{print $2}')
  else
    echo -e "${RED}오류: 'ip' 또는 'ifconfig' 명령을 찾을 수 없습니다. OS에 대한 버그를 제출하세요.${NC}"
    return 1
  fi
  echo $ip
}

get_external_ip() {
  external_ip=''
  external_ip=$(curl -s https://api.ipify.org)
  if [[ -z "$external_ip" ]]; then
    external_ip=$(curl -s http://checkip.dyndns.org | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
  fi
  if [[ -z "$external_ip" ]]; then
    external_ip=$(curl -s http://ipecho.net/plain)
  fi
  if [[ -z "$external_ip" ]]; then
    external_ip=$(curl -s https://icanhazip.com/)
  fi
  if [[ -z "$external_ip" ]]; then
    external_ip=$(curl --header  "Host: icanhazip.com" -s 104.18.114.97)
  fi
  if [[ -z "$external_ip" ]]; then
    external_ip=$(get_ip)
    if [ $? -eq 0 ]; then
      echo "IP 주소는: $IP"
    else
      external_ip="localhost"
    fi
  fi
  echo $external_ip
}

hash_password() {
  local input="$1"
  local hashed_password

  # openssl 사용 시도
  if command -v openssl > /dev/null; then
    hashed_password=$(echo -n "$input" | openssl dgst -sha256 -r | awk '{print $1}')
    echo "$hashed_password"
    return 0
  fi

  # shasum 사용 시도
  if command -v shasum > /dev/null; then
    hashed_password=$(echo -n "$input" | shasum -a 256 | awk '{print $1}')
    echo "$hashed_password"
    return 0
  fi

  # sha256sum 사용 시도
  if command -v sha256sum > /dev/null; then
    hashed_password=$(echo -n "$input" | sha256sum | awk '{print $1}')
    echo "$hashed_password"
    return 0
  fi

  return 1
}

if [[ $(docker-safe info 2>&1) == *"Cannot connect to the Docker daemon"* ]]; then
    echo -e "${RED}Docker 데몬이 실행 중이 아닙니다.${NC}"
    exit 1
else
    echo -e "${GREEN}Docker 데몬이 실행 중입니다.${NC}"
fi

CURRENT_DIRECTORY=$(pwd)

# 사용자 입력에 대한 기본값
DASHPORT_DEFAULT=8080
EXTERNALIP_DEFAULT=auto
INTERNALIP_DEFAULT=auto
SHMEXT_DEFAULT=9001
SHMINT_DEFAULT=10001
PREVIOUS_PASSWORD=none

GITLAB_IMAGE_NAME="registry.gitlab.com/shardeum/server:latest"
GITHUB_IMAGE_NAME="ghcr.io/shardeum/server:latest"

# GitLab 이미지로 컨테이너가 존재하는지 확인
GITLAB_CONTAINER_ID=$(docker-safe ps -qf "ancestor=$GITLAB_IMAGE_NAME")

# GitHub 이미지로 컨테이너가 존재하는지 확인
GITHUB_CONTAINER_ID=$(docker-safe ps -qf "ancestor=$GITHUB_IMAGE_NAME")

# 발견된 컨테이너에 따라 작업 결정
if [ ! -z "$GITLAB_CONTAINER_ID" ]; then
  echo "기존 GitLab 컨테이너가 발견되었습니다. ID: $GITLAB_CONTAINER_ID"
  # GitLab 컨테이너에 대한 작업 수행, 예: 설정 복사, 업그레이드
  CONTAINER_ID=$GITLAB_CONTAINER_ID
elif [ ! -z "$GITHUB_CONTAINER_ID" ]; then
  echo "기존 GitHub 컨테이너가 발견되었습니다. ID: $GITHUB_CONTAINER_ID"
  # GitHub 컨테이너에 대한 작업 수행, 예: 설정 복사, 업그레이드
  CONTAINER_ID=$GITHUB_CONTAINER_ID
else
  echo "기존 컨테이너가 발견되지 않았습니다. 새 설치를 진행합니다."
fi

if [ ! -z "${CONTAINER_ID}" ]; then
  echo "CONTAINER_ID: ${CONTAINER_ID}"
  echo "기존 컨테이너가 발견되었습니다. 컨테이너에서 설정을 읽는 중입니다."

  # read_container_settings의 출력을 변수에 할당
  if ! ENV_VARS=$(docker inspect --format="{{range .Config.Env}}{{println .}}{{end}}" "$CONTAINER_ID"); then
    ENV_VARS=$(sudo docker inspect --format="{{range .Config.Env}}{{println .}}{{end}}" "$CONTAINER_ID")
  fi

  if ! docker-safe cp "${CONTAINER_ID}:/home/node/app/cli/build/secrets.json" ./; then
    echo "컨테이너에 secrets.json이 없습니다."
  else
    echo "컨테이너에서 secrets.json을 재사용합니다."
  fi

  # 유효성 검사기가 이미 실행 중인지 확인
  set +e
  status=$(docker-safe exec "${CONTAINER_ID}" operator-cli status 2>/dev/null)
  check=$?
  set -e

  if [ $check -eq 0 ]; then
    # 명령이 성공적으로 실행됨
    status=$(awk '/state:/ {print $2}' <<< $status)
    if [ "$status" = "active" ] || [ "$status" = "syncing" ]; then
      read -p "노드가 $status 상태이며 업그레이드하면 노드가 네트워크를 예기치 않게 떠나고 스테이크 금액을 잃게 됩니다.
      지금 업그레이드하시겠습니까 (y/N)?" REALLYUPGRADE
      REALLYUPGRADE=$(echo "$REALLYUPGRADE" | tr '[:upper:]' '[:lower:]')
      REALLYUPGRADE=${REALLYUPGRADE:-n}

      if [ "$REALLYUPGRADE" == "n" ]; then
        exit 1
      fi
    else
      echo "유효성 검사기 프로세스가 온라인 상태가 아닙니다."
    fi
  else
    read -p "설치 프로그램이 기존 노드가 활성 상태인지 확인할 수 없습니다.
    활성 노드가 예기치 않게 네트워크를 떠나면 스테이크 금액을 잃게 됩니다.
    지금 업그레이드하시겠습니까 (y/N)?" REALLYUPGRADE
    REALLYUPGRADE=$(echo "$REALLYUPGRADE" | tr '[:upper:]' '[:lower:]')
    REALLYUPGRADE=${REALLYUPGRADE:-n}

    if [ "$REALLYUPGRADE" == "n" ]; then
      exit 1
    fi
  fi

  docker-safe stop "${CONTAINER_ID}"
  docker-safe rm "${CONTAINER_ID}"

  # 저장된 값으로 기본값 업데이트
  DASHPORT_DEFAULT=$(echo $ENV_VARS | grep -oP 'DASHPORT=\K[^ ]+') || DASHPORT_DEFAULT=8080
  EXTERNALIP_DEFAULT=$(echo $ENV_VARS | grep -oP 'EXT_IP=\K[^ ]+') || EXTERNALIP_DEFAULT=auto
  INTERNALIP_DEFAULT=$(echo $ENV_VARS | grep -oP 'INT_IP=\K[^ ]+') || INTERNALIP_DEFAULT=auto
  SHMEXT_DEFAULT=$(echo $ENV_VARS | grep -oP 'SHMEXT=\K[^ ]+') || SHMEXT_DEFAULT=9001
  SHMINT_DEFAULT=$(echo $ENV_VARS | grep -oP 'SHMINT=\K[^ ]+') || SHMINT_DEFAULT=10001
  PREVIOUS_PASSWORD=$(echo $ENV_VARS | grep -oP 'DASHPASS=\K[^ ]+') || PREVIOUS_PASSWORD=none
elif [ -f NODEHOME/.env ]; then
  echo "기존 NODEHOME/.env 파일이 발견되었습니다. 파일에서 설정을 읽는 중입니다."

  # NODEHOME/.env 파일을 변수에 읽기. 기존 설치 디렉토리를 사용합니다.
  ENV_VARS=$(cat NODEHOME/.env)

  # 저장된 값으로 기본값 업데이트
  DASHPORT_DEFAULT=$(echo $ENV_VARS | grep -oP 'DASHPORT=\K[^ ]+') || DASHPORT_DEFAULT=8080
  EXTERNALIP_DEFAULT=$(echo $ENV_VARS | grep -oP 'EXT_IP=\K[^ ]+') || EXTERNALIP_DEFAULT=auto
  INTERNALIP_DEFAULT=$(echo $ENV_VARS | grep -oP 'INT_IP=\K[^ ]+') || INTERNALIP_DEFAULT=auto
  SHMEXT_DEFAULT=$(echo $ENV_VARS | grep -oP 'SHMEXT=\K[^ ]+') || SHMEXT_DEFAULT=9001
  SHMINT_DEFAULT=$(echo $ENV_VARS | grep -oP 'SHMINT=\K[^ ]+') || SHMINT_DEFAULT=10001
  PREVIOUS_PASSWORD=$(echo $ENV_VARS | grep -oP 'DASHPASS=\K[^ ]+') || PREVIOUS_PASSWORD=none
fi

cat << EOF

############################
# 0. 사용자로부터 정보 받기  #
############################

EOF

read -p "웹 기반 대시보드를 실행하시겠습니까? (Y/n): " RUNDASHBOARD
RUNDASHBOARD=$(echo "$RUNDASHBOARD" | tr '[:upper:]' '[:lower:]')
RUNDASHBOARD=${RUNDASHBOARD:-y}

if [ "$PREVIOUS_PASSWORD" != "none" ]; then
  read -p "대시보드의 비밀번호를 변경하시겠습니까? (y/N): " CHANGEPASSWORD
  CHANGEPASSWORD=$(echo "$CHANGEPASSWORD" | tr '[:upper:]' '[:lower:]')
  CHANGEPASSWORD=${CHANGEPASSWORD:-n}
else
  CHANGEPASSWORD="y"
fi

read_password() {
  local CHARCOUNT=0
  local PASSWORD=""
  while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
  do
    # Enter - 비밀번호 수락
    if [[ $CHAR == $'\0' ]] ; then
      break
    fi
    # Backspace
    if [[ $CHAR == $'\177' ]] ; then
      if [ $CHARCOUNT -gt 0 ] ; then
        CHARCOUNT=$((CHARCOUNT-1))
        PROMPT=$'\b \b'
        PASSWORD="${PASSWORD%?}"
      else
        PROMPT=''
      fi
    else
      CHARCOUNT=$((CHARCOUNT+1))
      PROMPT='*'
      PASSWORD+="$CHAR"
    fi
  done
  echo $PASSWORD
}

if [ "$CHANGEPASSWORD" = "y" ]; then
  valid_pass=false
  while [ "$valid_pass" = false ] ;
  do
    echo -n -e "비밀번호 요구사항: 최소 8자, 최소 1개의 소문자, 최소 1개의 대문자, 최소 1개의 숫자, 최소 1개의 특수문자 !@#$%^&*()_+$ \n대시보드에 접근할 비밀번호를 설정하세요:"
    DASHPASS=$(read_password)

    # 비밀번호 길이 확인
    if (( ${#DASHPASS} < 8 )); then
        echo -e "\n잘못된 비밀번호! 너무 짧습니다.\n"

    # 최소 1개의 소문자 확인
    elif ! [[ "$DASHPASS" =~ [a-z] ]]; then
        echo -e "\n잘못된 비밀번호! 최소 1개의 소문자가 포함되어야 합니다.\n"

    # 최소 1개의 대문자 확인
    elif ! [[ "$DASHPASS" =~ [A-Z] ]]; then
        echo -e "\n잘못된 비밀번호! 최소 1개의 대문자가 포함되어야 합니다.\n"

    # 최소 1개의 숫자 확인
    elif ! [[ "$DASHPASS" =~ [0-9] ]]; then
        echo -e "\n잘못된 비밀번호! 최소 1개의 숫자가 포함되어야 합니다.\n"

    # 최소 1개의 특수문자 확인
    elif ! [[ "$DASHPASS" =~ [!@#$%^\&*()_+$] ]]; then
        echo -e "\n잘못된 비밀번호! 최소 1개의 특수문자 !@#$%^&*()_+$가 포함되어야 합니다.\n"

    # 비밀번호가 유효함
    else
        valid_pass=true
        echo "\n비밀번호가 성공적으로 설정되었습니다."
    fi
  done

  # 비밀번호 해싱
  DASHPASS=$(hash_password "$DASHPASS")
else
  DASHPASS=$PREVIOUS_PASSWORD
  if ! [[ $DASHPASS =~ ^[0-9a-f]{64}$ ]]; then
    DASHPASS=$(hash_password "$DASHPASS")
  fi
fi

if [ -z "$DASHPASS" ]; then
  echo -e "\n비밀번호 해싱에 실패했습니다. openssl이 설치되어 있는지 확인하세요."
  exit 1
fi

echo # 입력 후 줄바꿈
# echo "비밀번호가 저장되었습니다:" $DASHPASS #디버그: 입력된 비밀번호가 기록되었는지 테스트.

# 사용 중인 포트를 나열하는 함수
list_used_ports() {
  echo "현재 사용 중인 포트들은 다음과 같습니다. 중복되지 않게 해주세요:"
  ss -tuln | awk 'NR>1 {print $5}' | awk -F: '{print $NF}' | sort -n | uniq | paste -sd ', ' -
}

while :; do
  list_used_ports
  read -p "웹 기반 대시보드에 접근할 포트(1025-65536)를 입력하세요 (기본값 $DASHPORT_DEFAULT): " DASHPORT
  DASHPORT=${DASHPORT:-$DASHPORT_DEFAULT}
  [[ $DASHPORT =~ ^[0-9]+$ ]] || { echo "유효한 포트를 입력하세요"; continue; }
  if ((DASHPORT >= 1025 && DASHPORT <= 65536)); then
    DASHPORT=${DASHPORT:-$DASHPORT_DEFAULT}
    break
  else
    echo "포트가 범위를 벗어났습니다. 다시 시도하세요."
  fi
done

while :; do
  read -p "만약 수동으로 외부IP를 설정하려면 IPv4주소를 입력하세요. 아니라면 그냥 엔터를 누르세요.(기본값=$EXTERNALIP_DEFAULT): " EXTERNALIP
  EXTERNALIP=${EXTERNALIP:-$EXTERNALIP_DEFAULT}

  if [ "$EXTERNALIP" == "auto" ]; then
    break
  fi

  # 입력이 유효한 IPv4 주소인지 확인
  if [[ $EXTERNALIP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    # IP 주소의 각 숫자가 0-255 사이인지 확인
    valid_ip=true
    IFS='.' read -ra ip_nums <<< "$EXTERNALIP"
    for num in "${ip_nums[@]}"
    do
        if (( num < 0 || num > 255 )); then
            valid_ip=false
        fi
    done

    if [ $valid_ip == true ]; then
      break
    else
      echo "잘못된 IPv4 주소입니다. 다시 시도하세요."
    fi
  else
    echo "잘못된 IPv4 주소입니다. 다시 시도하세요."
  fi
done

while :; do
  read -p "먄약 수동으로 내부IP를 설정하려면 IPv4주소를 입력하세요.아니라면 그냥 엔터를 누르세요.(기본값=$INTERNALIP_DEFAULT): " INTERNALIP
  INTERNALIP=${INTERNALIP:-$INTERNALIP_DEFAULT}

  if [ "$INTERNALIP" == "auto" ]; then
    break
  fi

  # 입력이 유효한 IPv4 주소인지 확인
  if [[ $INTERNALIP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    # IP 주소의 각 숫자가 0-255 사이인지 확인
    valid_ip=true
    IFS='.' read -ra ip_nums <<< "$INTERNALIP"
    for num in "${ip_nums[@]}"
    do
        if (( num < 0 || num > 255 )); then
            valid_ip=false
        fi
    done

    if [ $valid_ip == true ]; then
      break
    else
      echo "잘못된 IPv4 주소입니다. 다시 시도하세요."
    fi
  else
    echo "잘못된 IPv4 주소입니다. 다시 시도하세요."
  fi
done

while :; do
  list_used_ports
  echo "Sphinx 네트워크에서 유효성 검사기를 실행하려면 방화벽에서 두 개의 포트를 열어야 합니다."
  read -p "이것은 노드 간의 p2p 통신을 허용합니다. p2p 통신을 위한 첫 번째 포트(1025-65536)를 입력하세요 (기본값 $SHMEXT_DEFAULT): " SHMEXT
  SHMEXT=${SHMEXT:-$SHMEXT_DEFAULT}
  [[ $SHMEXT =~ ^[0-9]+$ ]] || { echo "유효한 포트를 입력하세요"; continue; }
  if ((SHMEXT >= 1025 && SHMEXT <= 65536)); then
    SHMEXT=${SHMEXT:-9001}
  else
    echo "포트가 범위를 벗어났습니다. 다시 시도하세요."
  fi
  read -p "p2p 통신을 위한 두 번째 포트(1025-65536)를 입력하세요 (기본값 $SHMINT_DEFAULT): " SHMINT
  SHMINT=${SHMINT:-$SHMINT_DEFAULT}
  [[ $SHMINT =~ ^[0-9]+$ ]] || { echo "유효한 포트를 입력하세요"; continue; }
  if ((SHMINT >= 1025 && SHMINT <= 65536)); then
    SHMINT=${SHMINT:-10001}
    break
  else
    echo "포트가 범위를 벗어났습니다. 다시 시도하세요."
  fi
done

#APPSEEDLIST="archiver-sphinx.shardeum.org"
#APPMONITOR="monitor-sphinx.shardeum.org"
APPMONITOR="96.126.116.124"
RPC_SERVER_URL="https://atomium.shardeum.org"

cat <<EOF

${BOLD_GREEN}###############################
# 1. Compose 프로젝트 가져오기  #
###############################${NC}

EOF

if [ -d "$NODEHOME" ]; then
  if [ "$NODEHOME" != "$(pwd)" ]; then
    echo -e "${YELLOW}기존 디렉토리 $NODEHOME을 삭제합니다...${NC}"
    rm -rf "$NODEHOME"
  else
    echo -e "${RED}현재 작업 디렉토리를 삭제할 수 없습니다. 다른 디렉토리로 이동한 후 다시 시도하세요.${NC}"
  fi
fi

git clone -b dev https://github.com/shardeum/validator-dashboard.git ${NODEHOME} || { echo -e "${BOLD_RED}오류: 권한이 거부되었습니다. 스크립트를 종료합니다.${NC}"; exit 1; }
cd ${NODEHOME}
chmod a+x ./*.sh

cat <<EOF

${BOLD_YELLOW}##############################
# 2. .env 파일 생성 및 설정   #
##############################${NC}

EOF

SERVERIP=$(get_external_ip)
LOCALLANIP=$(get_ip)
cd ${NODEHOME} &&
touch ./.env
cat >./.env <<EOL
EXT_IP=${EXTERNALIP}
INT_IP=${INTERNALIP}
EXISTING_ARCHIVERS=[{"ip":"34.159.56.206","port":4000,"publicKey":"64a3833499130406550729ab20f6bec351d04ec9be3e5f0144d54f01d4d18c45"},{"ip":"3.76.189.189","port":4000,"publicKey":"44d4be08423dd9d90195d650fc58f41cc2fdeb833180686cdbcb3196fe113497"},{"ip":"69.164.202.28","port":4000,"publicKey":"2cfbc5a9a96591e149225395ba33fed1a8135123f7702abdb7deca3d010a21ee"}]
APP_MONITOR=${APPMONITOR}
DASHPASS=${DASHPASS}
DASHPORT=${DASHPORT}
SERVERIP=${SERVERIP}
LOCALLANIP=${LOCALLANIP}
SHMEXT=${SHMEXT}
SHMINT=${SHMINT}
RPC_SERVER_URL=${RPC_SERVER_URL}
NEXT_PUBLIC_RPC_URL=${RPC_SERVER_URL}
NEXT_EXPLORER_URL=https://explorer-atomium.shardeum.org
minNodes=640
baselineNodes=640
maxNodes=1200
nodesPerConsensusGroup=128
EOL

cat <<EOF

${BOLD_GREEN}#########################
# 3. 오래된 이미지 정리  #
#########################${NC}

EOF

./cleanup.sh

cat <<EOF

${BOLD_YELLOW}######################
# 4. 기본 이미지 빌드 #
######################${NC}

EOF

cd ${NODEHOME} &&
docker-safe build --no-cache -t local-dashboard -f Dockerfile --build-arg RUNDASHBOARD=${RUNDASHBOARD} .

cat <<EOF

${BOLD_GREEN}############################
# 5. Compose 프로젝트 시작  #
############################${NC}

EOF

cd ${NODEHOME}
if [[ "$(uname)" == "Darwin" ]]; then
  sed "s/- '8080:8080'/- '$DASHPORT:$DASHPORT'/" docker-compose.tmpl > docker-compose.yml
  sed -i '' "s/- '9001-9010:9001-9010'/- '$SHMEXT:$SHMEXT'/" docker-compose.yml
  sed -i '' "s/- '10001-10010:10001-10010'/- '$SHMINT:$SHMINT'/" docker-compose.yml
else
  sed "s/- '8080:8080'/- '$DASHPORT:$DASHPORT'/" docker-compose.tmpl > docker-compose.yml
  sed -i "s/- '9001-9010:9001-9010'/- '$SHMEXT:$SHMEXT'/" docker-compose.yml
  sed -i "s/- '10001-10010:10001-10010'/- '$SHMINT:$SHMINT'/" docker-compose.yml
fi
./docker-up.sh

echo -e "${GREEN}이미지를 시작합니다. 시간이 걸릴 수 있습니다...${NC}"
(docker-safe logs -f shardeum-dashboard &) | grep -q 'done'

# secrets.json이 존재하는지 확인하고 컨테이너 내부에 복사
cd ${CURRENT_DIRECTORY}
if [ -f secrets.json ]; then
  echo -e "${YELLOW}기존 노드를 재사용합니다.${NC}"
  CONTAINER_ID=$(docker-safe ps -qf "ancestor=local-dashboard")
  echo -e "${GREEN}새 컨테이너 ID는 : $CONTAINER_ID${NC}"
  docker-safe cp ./secrets.json "${CONTAINER_ID}:/home/node/app/cli/build/secrets.json"
  rm -f secrets.json
fi

# 들여쓰기 하지 마세요
if [ $RUNDASHBOARD = "y" ]
then
cat <<EOF
  ${BOLD_GREEN}웹 대시보드를 사용하려면:${NC}
    1. 노드에 연결하는 데 사용한 IP 주소를 기록하세요. 이는 외부 IP, LAN IP 또는 localhost일 수 있습니다.
    2. 웹 브라우저를 열고 웹 대시보드에 https://<노드 IP 주소>:$DASHPORT로 이동하세요.
    3. 설정 탭으로 이동하여 지갑을 연결하세요.
    4. 유지 관리 탭으로 이동하여 노드 시작 버튼을 클릭하세요.

  이 유효성 검사기가 클라우드에 있고 인터넷을 통해 대시보드에 접근해야 하는 경우,
  강력한 비밀번호를 설정하고 localhost 대신 외부 IP를 사용하세요.
EOF
fi

cat <<EOF

${BOLD_YELLOW}명령줄 인터페이스를 사용하려면:${NC}
	1. Shardeum 홈 디렉토리 ($NODEHOME)로 이동하세요.
	2. ./shell.sh로 유효성 검사기 컨테이너에 들어가세요.
	3. "operator-cli --help" 명령을 실행하세요.

EOF