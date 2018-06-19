#core_event files
AUX_SOURCE_DIRECTORY(. DIR_STU_CORE_EVENT_SRC)

#build core_event
ADD_LIBRARY(event ${DIR_STU_CORE_EVENT_SRC})
