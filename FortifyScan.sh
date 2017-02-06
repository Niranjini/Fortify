#!/usr/bin/env bash
# *****************************************************************************
# *****************************************************************************
# Purpose: Script to build the code & scan using Fortify SCA and upload the fpr report in SSC
# Created: 02/01/2014
# Author: Niranjini(na8@apple.com)
# Updated: 04/02/2014
#  [Niranjini: Modified code for Classpath if no jar files found in source code]
# Updated: 02/25/2014
#  [Niranjini : Modified the script to integrate OWASP Dependency Checker plugin to scan 3rd parties libraries]
# Updated: 09/08/2014
# [Niranjini : Updated the script to handle jar scan. if parameter JARSCAN_FLAG= Yes then jar scan is enabled
# Updated: 09/12/2014
#  [Niranjini : Included Additional parameter JAR_OWASPDEPENDENCY_CHECK to toggle OWASP Dependency Checker plugin to scan #3rd parties libraries]
#Updated: 09/16/2014
#  [Niranjini : Included Additional parameter MAVEN_PROJ to parse pom.xml and download all dependencies]
#  [Niranjini : Included for loop to translate each jar file individually and throw message along with jar name in the #console to track success/failure status individually]
# *****************************************************************************
export PATH=$PATH:$1
# *****************************************************************************
# Define the list of variables used in the script
# ********************************** *******************************************
#SSC_URL="http://17.207.107.141:8083/ssc"

SSC_URL=
PROJECT_FOLDER=$2
BUILD_ID=$3
SRC=$PROJECT_FOLDER
USE_64="-64"
JAVA_OPTS="-Xmx12288M -Xms600M -Xss24M -XX:MaxPermSize=256M"
#JAVA_CP=$(find $PROJECT_FOLDER -name '*.jar')
FPR_FILE="${BUILD_ID}.fpr"
LOG_TRANS="TRANSLOG_${BUILD_ID}.txt"
LOG_SCAN="SCANLOG_${BUILD_ID}.txt"
RPT_TEMPLATE=$6
CUSTOM_RULES="/ngs/app/etsqat/softwares/Fortify/Core/config/customrules/CustomRules.xml"
TRANS_FILE="translate_files.txt"
#[Niranjini]Token updated on 11/11/14
AUTHTOKEN=
PROJECT=$4
VERSION=$5
# *****************************************************************************

SCANSTART=`date`
echo -e "[Info]: SCAN STARTED AT ${SCANSTART}"
<<COMMENT
#Code for Build ID with Timestamp
DATE=$(date +"%Y%m%d%H%M")
BUILD_ID=$BUILDID"_"$DATE
mkdir $BUILD_ID
COMMENT


# ******************************************************************************
# Maven Project- install all the dependencies
# ******************************************************************************
if [[ $MAVEN_PROJ = YES || $MAVEN_PROJ = yes ]]
then
     export M2_HOME=/ngs/app/etsqat/softwares/apache-maven
     export M2=$M2_HOME/bin
     export PATH=$M2:$PATH
     export JAVA_HOME=/ngs/app/etsqat/softwares/jdk1.8.0_66
	 export PATH=$JAVA_HOME/bin:$PATH
     cd $PROJECT_FOLDER    
     mvn package
     cd ..
fi
# *****************************************************************************
# Untar .war files
# ******************************************************************************
WAR_FILE=$(find $PROJECT_FOLDER -name "*.war")
if [ -n "$WAR_FILE" ];
then
jar xvf $WAR_FILE
fi


# *****************************************************************************
# Deleting log, txt, pdf, and fpr files generated from previous scans
# *****************************************************************************

echo -e "[Info]: DELETING OLD FILES"

if [ -f $FPR_FILE ];
then
if rm $FPR_FILE
then
echo -e "[Info]: ... ${FPR_FILE} WAS DELETED"
else
echo -e "[Warning]: ... ISSUE DELETING ${FPR_FILE}"
fi
fi

# Delete old log files
if [ -f $LOG_TRANS ];
then
if rm ${LOG_TRANS}
then
echo -e "[Info]: ... ${LOG_TRANS} WAS DELETED"
else
echo -e "[Warning]: ... Issue deleting ${LOG_TRANS}"
fi
fi


if [ -f $LOG_SCAN ];
then
if rm ${LOG_SCAN}
then
echo -e "[Info]: ... ${LOG_SCAN} WAS DELETED"
else
echo -e "[Warning]: ... Issue deleting ${LOG_SCAN}"
fi
fi

if [ -f $TRANS_FILE ];
then
if rm ${TRANS_FILE}
then
echo -e "[Info]: ... ${TRANS_FILE} WAS DELETED"
else
echo -e "[Warning]: ... Issue deleting ${TRANS_FILE}"
fi
fi

# *****************************************************************************
# Clean our build to make sure there are no orphaned NST files
# *****************************************************************************
if sourceanalyzer -b $BUILD_ID -clean
then
echo -e "[Info]: ... NST FILES HAVE BEEN DELETED"
else
echo -e "[Warning]: ... ISSUE DELETING NST FILES"
fi
# *****************************************************************************

# *****************************************************************************
# Translate our source code to NST
# *****************************************************************************

# Translating the Source
# *****************************************************************************

echo -e "[Info]: STARTING TRANSLATION"
if [ -n "$JAVA_CP" ];
then
     if sourceanalyzer -b ${BUILD_ID} ${USE_64} ${JAVA_OPTS} -source ${JAVA_VER} -cp ${JAVA_CP} ${SRC} -logfile ${LOG_TRANS}
     then
        echo -e "[Info]: ... FINISHED TRANSLATING JAVA SOURCE"
     else
        echo -e "[Error]: ... ISSUE TRANSLATING JAVA SOURCE SEE LOG FILE ${LOG_TRANS}."
        exit -1
     fi

else
if sourceanalyzer -b ${BUILD_ID} ${USE_64} ${JAVA_OPTS} -source ${JAVA_VER} ${SRC} -logfile ${LOG_TRANS}
then
echo -e "[Info]: ... FINISHED TRANSLATING JAVA SOURCE"
else
echo -e "[Error]: ... ISSUE TRANSLATING JAVA SOURCE SEE LOG FILE ${LOG_TRANS}."
exit -1
fi
fi

#--------------------------------------------------
# Scan for JAR files if parameter JARSCAN_FLAG=Yes 
#---------------------------------------------------

if [[ $JARSCAN_FLAG = YES || $JARSCAN_FLAG = yes ]]
then 
for ((intIndex=0; intIndex<$count; ++intIndex ))
do 
echo -e "[Info]: ... STARTED TRANSLATING JAR FILES: ${JAR_PATH_INCLUDED[$intIndex]}"
if sourceanalyzer -b ${BUILD_ID} ${USE_64} ${JAVA_OPTS} -source ${JAVA_VER} -Dcom.fortify.sca.fileextensions.jar=ARCHIVE -Dcom.fortify.sca.fileextensions.class=BYTECODE -cp $PROJECT_FOLDER/**/*.jar ${JAR_PATH_INCLUDED[$intIndex]} -debug -logfile ${LOG_TRANS}
  then
     echo -e "[Info]: ... FINISHED TRANSLATING JAR FILES: ${JAR_PATH_INCLUDED[$intIndex]}"
  else
     echo -e "[Error]: ... ISSUE TRANSLATING JAR FILES."
     exit -1
  fi
done
 fi


# *****************************************************************************
#OWASP DEPENDENCY CHECKER - 3rd party libraries scan
# ******************************************************************************
if [[ $JAR_OWASPDEPENDENCY_CHECK = YES || $JAR_OWASPDEPENDENCY_CHECK = yes ]]
then 
if bash /ngs/app/etsqat/softwares/dependency-check/bin/dependency-check.sh -a $PROJECT_FOLDER -f XML -s $PROJECT_FOLDER/ 
then
  echo -e "[Info]: ... OWASP Dependency checker- 3rd party libraries scanned Successfully"
else
 echo -e "[Info]: ... OWASP Dependency checker- 3rd party libraries scanned Failed"
fi
fi 
# *****************************************************************************

# Get a list of all the files that were scanned
# *****************************************************************************
if sourceanalyzer -b ${BUILD_ID} -show-files > ${TRANS_FILE}
then
echo -e "[Info]: ... LIST OF TRANSLATED FILES WRITTEN TO ${TRANS_FILE}"
else
echo -e "[Warning]: ... ISSUE WRITING LIST OF TILES TO FILE."
fi

# *****************************************************************************
# Get a list of all the warnings generated during the translate phase
# *****************************************************************************
if sourceanalyzer -b ${BUILD_ID} -show-build-warnings > build_warnings.txt
then
echo -e "[Info]: ... LIST OF BUILD WARNINGS WRITTEN TO build_warnings.txt"
else
echo -e "[Warning]: ... ISSUE WRITING LIST OF BUILD WARNINGS TO FILE."
fi
# *****************************************************************************

#TRANS_FILE="translate_files.txt"
if [ -s ${TRANS_FILE} ]
then


# *****************************************************************************
# Analyze the code
# *****************************************************************************
echo -e "[Info]: ANALYZING CODE FOR POTENTAIL SECURITY VULNERABILITIES"

if sourceanalyzer -b ${BUILD_ID} ${USE_64} ${JAVA_OPTS} -scan -f ${BUILD_ID}.fpr -rules ${CUSTOM_RULES} -logfile ${LOG_SCAN}
then
echo -e "[Info]: ... CODE ANALYSIS FOR ${BUILD_ID} COMPLETED SUCCESFULLY"
else
echo -e "[Error]: ... THERE WAS AN ISSUE ANALYZING THE CODE SEE ${LOG_SCAN} FOR DETAILS"
exit -1
fi
# *****************************************************************************

echo -e "[Info]: VALIDATING ${BUILD_ID}.fpr"
if FPRUtility -information -signature -project ${BUILD_ID}.fpr
then
echo -e "[Info]: ... FPR SIGNATURE IS VALID"
echo -e "[Info]: ... UPLOADING FPR TO SSC"
#**************************************************************************
# The file is valid & upload it to the SSC server
#**************************************************************************
if fortifyclient -url ${SSC_URL} uploadFPR -file ${BUILD_ID}.fpr -project ${PROJECT} -version ${VERSION} -authtoken ${AUTHTOKEN}
then
echo -e "[Info]: ... FPR UPLOADED SUCCESFULLY"
else
echo -e "[Error]: ... THERE WAS AN ISSUE UPLOADING THE FPR" | tee -a ${SCAN_LOG}
exit -1
fi

# *****************************************************************************

if ReportGenerator -template ${RPT_TEMPLATE} -format xml -f ${BUILD_ID}.xml -source ${BUILD_ID}.fpr
then
echo -e "[Info]: ... REPORT ${BUILD_ID}.xml GENERATED SUCCESFULLY"
#if python "/ngs/app/etsqat/.jenkins/jobs/fxml2xlsx.py" -i ${BUILD_ID}.xml -o ${BUILD_ID}.xlsx
#then
#echo -e "[Info]: ... REPORT ${BUILD_ID}.xlsx GENERATED SUCCESFULLY"
#fi
else
echo -e "[Error]: ... ISSUE GENERATING xml REPORT"
#echo -e "[Error]: ... ISSUE GENERATING xlsx REPORT"
exit -1
fi

else
echo -e "[Warning]: ... FPR SIGNATURE IS NOT VALID"
fi
else
echo "ISSUE TRANSLATING JAVA SOURCE.SCAN ABORTED"
exit -1
fi



SCANEND=`date`
echo -e "[Info]: SCAN FOR ${BUILD_ID} COMPLETED AT ${SCANEND}"
exit 0
