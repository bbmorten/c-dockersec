
## Default Bridge Network (No resolution)

docker rm -f mongodb
docker rm -f mongo-express

docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=pass \
  mongo:latest

docker run -d \
  --name mongo-express \
  -p 8081:8081 \
  -e ME_CONFIG_MONGODB_ADMINUSERNAME=admin \
  -e ME_CONFIG_MONGODB_ADMINPASSWORD=pass \
  -e ME_CONFIG_MONGODB_SERVER=mongodb \
  mongo-express:latest

##  Custom Network

docker rm -f mongodb
docker rm -f mongo-express

### Create custom network

docker network create mongo-network

### Run MongoDB

docker run -d \
  --name mongodb \
  --rm \
  --network mongo-network \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=pass \
  mongo:latest

### Run MongoDB Express

docker run -d \
  --name mongo-express \
  --network mongo-network \
  --rm \
  -p 8081:8081 \
  -e ME_CONFIG_MONGODB_ADMINUSERNAME=admin \
  -e ME_CONFIG_MONGODB_ADMINPASSWORD=pass \
  -e ME_CONFIG_MONGODB_SERVER=mongodb \
  mongo-express:latest

docker run -d --name test1 busybox sleep 3600
docker exec test1 ip addr
docker run -d --name test2 --network host busybox sleep 3600
docker exec test2 ip addr
docker run -d --name test3 --network host nginx
docker run -d --name test4 --network none busybox sleep 3600

---

# Day 5

## Lab1 on DockerSec (review it)

- nginx.conf example

## dot.net app

<http://ndawn.btegitim.com:8014/99-Samples/containerize-net-app/>

## PID namespace lab

<http://ndawn.btegitim.com:8018/docs/Examples/pid_namespaces_lab>

## Docker context

### If you need to specify a specific SSH user

docker context create remote-docker-144 \
  --description "Remote Docker daemon on 192.168.48.144" \
  --docker "host=ssh://vm@192.168.48.144"

### List all Docker contexts

docker context ls

### Switch to the remote context

docker context use remote-docker

### Test the connection

docker version
docker ps

### Switch back to local context when needed

docker context use default

### Context management

#### List contexts

docker context ls

#### Show current context

docker context show

#### Remove a context

docker context rm remote-docker

#### Export context for sharing

docker context export remote-docker

#### Import context

docker context import remote-docker remote-docker.dockercontext

## Claude Desktop

```claude_desktop_config.json
{
    "mcpServers": {
        "puppeteer": {
            "command": "docker",
            "args": [
                "run",
                "-i",
                "--rm",
                "--init",
                "-e",
                "DOCKER_CONTAINER=true",
                "mcp/puppeteer"
            ]
        },
        "kubernetes": {
            "command": "npx",
            "args": [
                "mcp-server-kubernetes"
            ]
        },
        "MCP_DOCKER": {
            "command": "docker",
            "args": [
                "mcp",
                "gateway",
                "run"
            ]
        }
    }
}
```

## Trivy, Synk, falco, sysdig

## Seccomp profile

/Users/bulent/git-msp/c-dockersec/pages/docs/Labs/lab-seccomp

## apparmor profile

## tmpfs

<https://docs.docker.com/reference/cli/docker/container/run/#tmpfs>

## privileged

<https://docs.docker.com/reference/cli/docker/container/run/#privileged>

## security-opt

<https://docs.docker.com/reference/cli/docker/container/run/#security-opt>
