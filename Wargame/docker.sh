if [[ "$#" -lt "2" ]]
then
    echo "docker.sh <image_name> <container_name>"
elif [[ "$#" -gt "2" ]]
then
    echo "docker.sh <image_name> <container_name>"
else
    IMAGE_NAME=$1 CONTAINER_NAME=$2
    docker build . -t $IMAGE_NAME
    docker run -d -t --privileged --name=$CONTAINER_NAME $IMAGE_NAME
    docker exec -it -u root $CONTAINER_NAME bash
fi