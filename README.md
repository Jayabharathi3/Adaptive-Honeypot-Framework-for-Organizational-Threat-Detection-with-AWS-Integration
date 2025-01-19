# Adaptive Honeypot Framework for Organizational Threat Detection with AWS Integration

# TEAM MEMBERS:
1. Prasannalakshmi G
2. Jayabharathi S
3. Varsha Sharon E

## Title of the Project
Adaptive Honeypot Framework for Organizational Threat Detection with AWS Integration
A scalable, adaptive honeypot framework leveraging AWS for real-time organizational threat detection and response.

## About
<!--Detailed Description about the project-->
The Adaptive Honeypot Framework for Organizational Threat Detection is a dynamic and scalable solution designed to enhance cybersecurity in organizational environments. This framework leverages AWS services to provide a flexible and robust platform for detecting, monitoring, and responding to cyber threats in real time. With its adaptive design, the honeypot adjusts to evolving threat landscapes and attacker behaviors, ensuring comprehensive protection. Key features include real-time monitoring to capture and analyze attack patterns, automated responses based on threat severity, and detailed threat intelligence reporting to improve system resilience. The integration with AWS ensures scalability and efficient handling of high traffic loads, making it suitable for organizations of all sizes. By incorporating advanced detection algorithms, architectural designs, and comprehensive testing, this project aims to provide a proactive and cost-effective solution for safeguarding against modern cyber threats.


## Features
<!--List the features of the project as shown below-->
- Adaptive Threat Detection
- Real-Time Monitoring
- Automated Response Mechanisms
- Scalable and Flexible Architecture
- Threat Intelligence Reporting and Adaptive System Design.
- Real-Time Data Logging and Proactive Security Posture.

## Requirements
<!--List the requirements of the project as shown below-->
* Operating System: Kali Linux (or any preferred Linux distribution) running on VirtualBox.
* Database: MySQL or MongoDB for storing captured threat data and analysis results.
* Programming Languages: Python (e.g., Scapy, Flask) for honeypot implementation and AWS SDK integration.
* Tools and Frameworks:
     - Nmap and Wireshark for network analysis.
     - ELK Stack (Elasticsearch, Logstash, Kibana) for data visualization.
     - Snort or Suricata for intrusion detection.
     - cowrie framework runs fake SSH/Telnet service that mimics a real server.
* AWS Services:
     - EC2: For hosting the honeypot instances.
     - S3: For storing logs and threat intelligence data.
     - Lambda: For automated responses and event-driven workflows.
     - CloudWatch: For monitoring and alerting.

## System Architecture
<!--Embed the system architecture diagram as shown below-->
This graphic provides a concise and understandable description of all the entities currently integrated into the system. The diagram shows how the many actions and choices are linked together. You might say that the whole process and how it was carried out is a picture. The figure below shows the functional connections between various entities.

![image](https://github.com/user-attachments/assets/0cf6d94e-a583-416d-aeed-375a6ba5b829)

## System Implementation
## Module 1: Data Collection and Preprocessing

Data Collection:  
Gather network data, including malicious traffic, unauthorized access attempts, malware activity, port scans, and exploits, from sources like honeypots, IDS, and threat intelligence feeds. Honeypots simulate vulnerabilities to attract diverse attack data.  

Data Labeling:  
Label data by attack type, phase, and severity, ensuring granularity and accuracy to support supervised learning.  

Preprocessing:  
1. **Feature Extraction:** Key attributes like IP, port, protocol, and timestamp.  
2. **Data Transformation:** Convert data to numerical formats, tokenize logs, and encode categories.  
3. **Normalization:** Scale features for consistent model input.  

## Module 2: Model Training

Train models using diverse datasets like NSL-KDD or CICIDS2017. Apply preprocessing steps, including feature selection (e.g., PCA, RFE), to enhance efficiency. Choose algorithms based on detection needs:  
- Machine Learning: Intrusion Detection System, DBSCAN (Density-Based Spatial Clustering of Applications with Noise), Random Forest, SVM for classification.  

Split data into training, validation, and testing sets. Optimize with hyperparameter tuning and evaluate using metrics like precision and recall to ensure robust performance.

### Module 3: Prediction of Output

Use the trained model to analyze real-time network data, detect threats, and classify attack types. The system assigns threat scores and generates alerts for administrators, detailing critical information like IP and protocols.  

Post-Processing:
- Apply thresholding to reduce false positives.  
- Filter and deduplicate alerts for clarity.  

This module ensures rapid and accurate threat detection to support cybersecurity efforts.

## CODING
```
//  Set Up AWS EC2 Instance for Honeypot

- aws ec2 run-instances --image-id ami-xxxxxxxxxxxxxxxxx --count 1 --  instance-type t2.micro --key-name your-key-pair --security-group-ids sg-xxxxxxxx --subnet-id subnet-xxxxxxxx --region us-east-1

- ssh -i "your-key-pair.pem" ubuntu@your-ec2-public-ip
-sudo apt update
-sudo apt install python3-pip python3-dev libssl-dev libffi-dev build-essential
-sudo pip3 install --upgrade pip

-cd cowrie
-python3 -m venv cowrie-env
-source cowrie-env/bin/activate
-pip install -r requirements.txt
```
```
//  Set Up Security Groups

- aws ec2 create-security-group --group-name HoneypotSG --description "Honeypot Security Group

- aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx --protocol tcp --port 22 --cidr 

- aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx --protocol tcp --port 23 --cidr 0.0.0.0/0
```
```
//Configure AWS CloudWatch for Monitoring

- aws logs create-log-group --log-group-name HoneypotLogs
- sudo apt install amazon-cloudwatch-agent

- sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
```
```
//Set Up AWS Lambda for Automated Response

- aws lambda create-function --function-name BlockMaliciousIP --runtime python3.8 --role  arn:aws:iam::your-account-id:role/your-lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip

-aws cloudwatch put-metric-alarm --alarm-name "SuspiciousActivityAlarm" --metric-name "NetworkPacketsIn" --namespace "AWS/EC2" --statistic Sum --period 60 --threshold 1000 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions arn:aws:swf:your-lambda-function
```
```
// Set Up a Bastion Host for Secure Access

-aws ec2 run-instances --image-id ami-xxxxxxxxxxxxxxxxx --instance-type t2.micro --key-name bastion-key-pair --security-group-ids sg-xxxxxxxx --subnet-id subnet-xxxxxxxx --region us-east-1
```
```
// Example code for IP blocking (bash / python)

import boto3
ec2 = boto3.client('ec2')
def lambda_handler(event, context):
    ip_address = event['ip']
    response = ec2.revoke_security_group_ingress(
        GroupId='sg-xxxxxxxx',
        CidrIp=f'{ip_address}/32',
        IpProtocol='tcp',
        FromPort=22,
        ToPort=22)
    return response
```
```
 // Monitor and Analyze

-aws es create-elasticsearch-domain --domain-name honeypot-logs --elasticsearch-version 7.10
```
```
 // Scaling and Auto-Scaling 

- aws autoscaling create-auto-scaling-group --auto-scaling-group-name honeypot-auto-scaling --min-size 1 --max-size 3 --desired-capacity 1 --launch-configuration-name honeypot-launch-config --vpc-zone-identifier subnet-xxxxxxxx
```
```


// To create your customized docker compose file

1.Go to cd ~/tpotce/compose.
2.Run python3 customizer.py.
3.The script will guide you through the process of creating your own docker-compose.yml. As some honeypots and services occupy the same ports it will check if any port conflicts are present and notify regarding the conflicting services. You then can resolve them manually by adjusting’
 docker-compose-custom.yml 
4.Stop T-Pot with 
systemctl stop tpot.
5.Copy the custom docker compose file: 
cp docker-compose-custom.yml ~/tpotce and cd ~/tpotce.
6.Check if everything works by running 
docker-compose -f docker-compose-custom.yml up. 
7.If everything works just fine press CTRL-C to stop the containers and run 
docker-compose -f docker-compose-custom.yml down -v.
8.Replace docker compose file with the new and successfully tested customized docker compose file
 mv ~/tpotce/docker-compose-custom.yml ~/tpotce/docker-compose.yml.
9.Start T-Pot with
 systemctl start tpot.

```
```
// Logs :

-systemctl stop tpot
-grc netstat -tulpen
-mi ~/tpotce/docker-compose.yml
-docker-compose -f ~/tpotce/docker-compose.yml up
-docker-compose -f ~/tpotce/docker-compose.yml down -v
```

## OUTPUT:

<!--Embed the Output picture at respective places as shown below as shown below-->
## HOMEPAGE: 

![image](https://github.com/user-attachments/assets/af73075f-76ca-445f-8c9d-e1cc5e07fd04)

On the T-Pot Landing Page just click on Kibana and you will be forwarded to Kibana. You can select from a large variety of dashboards and visualizations all tailored to the T-Pot supported honeypots.

## KIBANA DASHBOARD (DATA VISUALIZATION):

![EqrmlFe - Imgur](https://github.com/user-attachments/assets/3c6ac404-9afe-4ab1-a8ba-c1c04949074f)

![kekee](https://github.com/user-attachments/assets/0549f89d-e752-4251-9216-d8c95422f61d)


The Kibana dashboard in T-Pot is an intuitive, web-based interface used for visualizing, analyzing, and managing data collected by the T-Pot honeypot framework. T-Pot integrates multiple honeypots and security tools to detect and analyze malicious activities, and Kibana serves as the visualization layer for this data.

## ATTACK MAP:

![kekekekeke](https://github.com/user-attachments/assets/7d15a073-2f7f-43d1-8582-21e20c690926)

The Attack Map in T-Pot’s Kibana dashboard is a dynamic visualization that showcases real-time and historical attack data, represented geographically. It plots the source and destination of cyberattacks on a world map, using lines and markers to indicate the flow of malicious traffic. Each attack is color-coded based on attributes like honeypot type, attack method, or severity, making it easy to differentiate between various threats. This map provides an instant overview of where attacks originate and their targeted regions, helping analysts identify hotspots of malicious activity globally.
In addition to its visual appeal, By correlating geographic data with other attack metrics, organizations can uncover patterns, such as regions frequently launching specific types of attacks or the recurrence of particular IPs. This data-driven insight aids in threat intelligence gathering and proactive defense planning, making the Attack Map an essential feature for monitoring and analyzing cyber threats.

## CYBER CHEF:

![image](https://github.com/user-attachments/assets/85eb157f-a679-4e5b-b6f9-bdc2b67cb0ed)

On the T-Pot Landing Page just click on Cyberchef and you will be forwarded to Cyberchef. CyberChef, often referred to as "The Cyber Swiss Army Knife," is a web-based tool designed for performing various data analysis and manipulation tasks in cybersecurity, data science, and other technical fields. Developed by GCHQ, CyberChef provides a user-friendly interface for executing a wide range of operations, such as encoding, decoding, encryption, decryption, data extraction, and format conversion, all without requiring specialized programming skills.
Key features of CyberChef include its drag-and-drop functionality for building "recipes," which are sequences of operations applied to input data. Users can easily combine multiple operations, such as converting data to Base64, decompressing a file, or searching for patterns using regular expressions, into a single workflow. CyberChef supports a vast library of operations, making it an essential tool for cybersecurity professionals, and developers to streamline data processing and analysis efficiently.

## Top 10 Countries by Event Count in Honeypot Systems:

![top10countries](https://github.com/user-attachments/assets/4a9c1b23-a4a0-4200-b480-e973bd16895c)

The adaptive honeypot framework that is fused with Amazon Web Services ensures that real-time cyber threats detected can be analyzed and visualized in a system with ease. The Figure 7.1 illustrates the distribution of events across the top 10 countries, revealing where in the world these malicious activities started. Then it will incorporate the adaptive honeypot framework with AWS so that data is seamlessly processed and stored to find malicious activities in precise ways by precise visualization. As shown, China leads the total with 49.6%, followed by the United States at 25.6%, which puts emphasis on the fact that dangerous activities are rampant within technologically advanced regions. Other contributors include Taiwan (4.8%), Russia (4.1%), and South Korea (3.4%), which indicate the worldwide nature of cyber threats that require localized and internationalized defense mechanisms.

## Event Count by Protocol in Honeypot Systems:

![eventcoun](https://github.com/user-attachments/assets/ab221449-d975-4500-8cf4-ab930bbb0826)

As can be inferred from Figure 7.2, an in-depth protocol-level analysis shows the most targeted protocol is TCP with events over 7,000. UDP and ICMP have several thousand events less than that. This can be considered a preference among attackers for reliable communication protocols: those supporting web servers or SSH, for example but also leveraging UDP and ICMP for amplification as well as reconnaissance attacks. The AWS-enabled honeypot system allows for real-time tracking of these events and provides actionable insights for securing network infrastructure. Together, these visualizations underscore the importance of advanced honeypot frameworks in identifying, analyzing, and mitigating evolving cyber threats effectively.

##  Time Series of Honeypot Systems:

![kkkk](https://github.com/user-attachments/assets/eaf516c3-01c4-4768-b8cd-b4c48df7630c)

The graph in Figure 7.3 indicates the daily count of captured events. Sharp rise from March 4, indicates that attackers soon discover this system and it has strong activity till March 8, indicating the engagement activity and exploitation attempts. Rapid drop on March 9 may be attributed to shift in focus or decreased attraction of the honeypot. It can better resolve time, be dynamically interactive, and vary representation of attacker activities compared to traditional honeypots. These characteristics facilitate further insight into the forms and patterns of attacks so it has become the current benchmark for honeypot systems and encourages real-time capability for threat identification.

##  Geolocation-Based Anomaly Detection in Honeypots:

![scatterplot](https://github.com/user-attachments/assets/796404ca-e496-4704-8f28-b0c565ff05bd)

The scatter plot in Figure 7.4 visualizes geolocation data with anomalies identified, plotting longitude on the x-axis and latitude on the y-axis.The blue markers show normal activity, and the red ones indicate anomalies. Concentration of the blue markers points out places that may often be targeted or monitored; however, the spread of red markers indicates anomalous geolocations that can be considered outliers or rare sources of attacks. This visualization compared to a traditional honeypot shows improved geospatial analysis abilities that provide a clear cut between normal and anomalous behavior. This improves the ability to detect unusual origins of attackers, which was not as common in previous systems and supports better-informed location-specific threat responses.

##  Port-Based Anomaly Detection in Honeypot:

![scatter1](https://github.com/user-attachments/assets/90697ae7-0075-41d5-81c7-44a922e931ed)

This scatter plot in Figure 7.5 visualizes the relationship between source ports (x-axis) and destination ports (y-axis) in honeypot data, distinguishing between normal activity (blue points) and anomalies (red points). The clustering of blue points near lower port numbers reflects typical port usage patterns, likely representing legitimate or common network behaviors. In contrast, the dispersed red points across higher port ranges highlight anomalous activities, often linked to irregular or malicious attempts, such as port scans, unusual traffic, or exploitation efforts.


##  Geospatial Clusters of Malicious Activity Detected by DBSCAN:

![cluster](https://github.com/user-attachments/assets/e4b36f12-600c-4b04-bc7b-e4d0838005cd)

Unlike previous honeypot systems, the current visualization offers more enhanced functionalities in the detection of anomalies through port activity. Traditional honeypots were mostly deficient in granularity and real-time analytical capabilities to identify fine-grained differences. This new approach allows network forensics by linking patterns of port usage with abnormal behaviors, hence providing a deeper understanding of attack methodologies and weaknesses. Such understanding supports proactive security measures and enhances the general effectiveness of threat detection systems.

This visualization in Figure 7.6 represents the geolocation clusters identified using the DBSCAN algorithm, which is very effective for analyzing honeypot data. Unlike other techniques, such as k-means, DBSCAN adaptively identifies clusters by checking density, allowing clusters with irregular shapes and noise to be identified, as in cluster `-1`. The identified clusters represent areas with increased activity, and the larger clusters, such as Cluster 0, represent areas with significant malicious traffic. The smaller clusters and noise points represent isolated or sporadic attacks, such as reconnaissance or probing activities. This approach is particularly beneficial for honeypot research because it can easily adapt to different data distributions without requiring any preliminary assumptions about the number of clusters. It brings out novel insights into regional attack patterns, which are helpful in prioritizing resources and in identifying emerging threats. This method is much more scalable than older methods of clustering, captures real-life attack behaviors, and is useful for more effective threat analysis in honeypot systems.

## Cluster Size Distribution in Geolocation Analysis (DBSCAN):

![cluster2](https://github.com/user-attachments/assets/27ef43e7-0900-4338-bbd4-a49c50863e9a)

The bar chart in Figure 7.7 provides valuable insights into data distribution across clusters identified by the DBSCAN algorithm. Cluster `0`, containing over 7,000 points, highlights a region of high activity, signaling a concentration of frequent or intense attacks. Cluster `1`, with around 2,000 points, represents another significant area, though less dense compared to Cluster `0`. Smaller clusters, ranging from `2` to `5`, depict localized or minor activities, possibly indicating more specific attack patterns or isolated events. Noise points, denoted as `-1`, signify outliers or anomalies in the data, reflecting abnormal behavior that deviates from standard attack patterns. This distribution indicates the possibility of the DBSCAN algorithm properly detecting high-density areas and noise points as well, although minor discrete clusters-thus describing a comprehensive overview of geolocation-oriented attacking patterns. Such insights enhance the efficiency of honeypot research by identifying regions of high concentration of threat activities and unique anomalies, hence a more comprehensive and accurate assessment of the attackers' behavior and strategies. This will help better understand the geospatial attack dynamics and create more precise and proactive cybersecurity strategies.

## Proportion of Normal and Anomalous Events Detected:

![anamoly](https://github.com/user-attachments/assets/b2034e85-858b-4ddd-af8c-70b8eb9deeb5)

The pie chart in Figure 7.8 reflects comparative frequency of normal and anomalous events that are resolved in the dataset. 96% are normal events - or typical and expected to occur. The remaining 4% of the whole represents anomalous events potentially of suspicious and irregular character and thus worth more investigating. The small percentage of anomalies proves that the detection system is capable of distinguishing between unusual patterns and normal behavior, an essential feature in honeypot and intrusion detection research studies for the identification of unusual yet crucial threats.

## Results and Impact
<!--Give the results and impact as shown below-->
The Adaptive Honeypot Framework successfully delivers a scalable and dynamic solution for real-time organizational threat detection and response. It efficiently traps and analyzes malicious activities, such as spambots, brute-force attacks, and malware, while leveraging AWS to ensure scalability and robust performance under high traffic. The framework enhances security by triggering automated responses, such as blocking malicious IPs and notifying administrators, reducing manual intervention. Additionally, it generates detailed threat intelligence reports, providing actionable insights for improving cybersecurity strategies. Its adaptive design ensures the system remains effective against evolving attacker behaviors, strengthening the organization’s overall security posture.

## Articles published / References
1. Brown, C., et al. (2017). Real-time adaptive honeypot system for the detection of network-based attacks. *International Journal of Network Security*, 19(5), 675-682.
2. Fadlullah, Z. M., et al. (2017). Fighting against cyber terrorism: The need for a new research focus. *IEEE Communications Magazine*, 55(2), 122-128.
3. Shiravi, A., Shiravi, H., & Ghorbani, A. A. (2012). A survey of visualization systems for network security. *IEEE Transactions on Visualization and Computer Graphics*, 18(8), 1313-1329.
4. Liu, H., Lang, B., & Liu, Y. (2021). CNN and RNN based payload classification model for network intrusion detection. *Computers & Security*, 99, 102053.
5. Mokbal, M., et al. (2020). Advanced honeypot technology for real-time detection and prevention of cyberattacks in smart cities. *Journal of Information Security and Applications*, 54, 102551.







