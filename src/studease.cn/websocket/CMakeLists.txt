#websocket files
AUX_SOURCE_DIRECTORY(. DIR_STU_WEBSOCKET_SRC)

#build websocket
ADD_LIBRARY(websocket ${DIR_STU_WEBSOCKET_SRC})
