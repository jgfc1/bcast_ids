# BCAST_IDS: A Network Intrusion Detection System

## Abstract
Network intrusion is a threat with severe impacts, which can damage in several ways to network infrastructures and digital assets in the common cyberspace. A modern technique most commonly employed to combat network intrusion is the development of attack detection systems using Machine Learning and Data Mining. These approaches can help to protect networks because they are able to identify and disconnect malicious network traffic. BCAST_IDS is a Network Intrusion Detection System (NIDS), which attempts to identify unauthorized and anomalous behaviour in a Local Area Network. For that, it monitors network activity on one network segment. Then, the system constantly performs analysis and watches for certain traffic patterns. If the detected traffic patterns match the defined policies in the Machine Learning model, a security alert is generated.

## Machine Learning in BCAST_IDS
Machine Learning and Data Mining techniques work by establishing an implicit or explicit model which enables to categorize the analized patterns. Since the network intrusion and Malware activity can be considered as anomalies, the system uses an algorithm that explicitly identifies anomalies (outliers) called **Isolation Forest**. In principle, outliers are less frequent than regular observations and are different from them in terms of values (they lie further away from the regular observations in the feature space). 

This algorithm is built on the basis of decision trees and the main idea of identifying normal and abnormal activity is in the path length of the tree. A normal point requires more partitions to be identified than abnormal point.

There are three phases to make this project comes true:
1. **Preprocessing:** feature selection and feature extraction. The data instances that are colleted from the network environment are structured.
2. **Training:** the Machine Learning algorithm is used and extracts patterns from the data collected previously. Then, a system model is built.
3. **Detection:** the monitored traffic data will be used as system input to be compared to the generated system model. If the pattern of the observation is matched with an existing threat, an alarm will be triggered and it will indicate a feasible network intrusion.

The following picture represents an overview of the BCAST_IDS architecture:

[picture]

### Dataset Generation and Preprocessing
The training dataset can be collected from a real-world connected environment. At this point, the importante features have to be identified. There are a whole bunch of features that can be monitored by networking tools for network analysis over the network, but some of them coukd be redundant. In particular, we have selected fifteen features and are listed in the next table:

| Feature  | Description |
| ------------- | ------------- |
| MAC  | MAC address  |
| num_MAC  | Total network packets generated from a specific MAC address |
| UCAST  | Total UNICAST traffic generated from a specific MAC address |
| MCAST  | Total MULTICAST traffic generated from a specific MAC address  |
| BCAST  | Total BROADCAST traffic generated from a specific MAC address  |
| ARPrq  | Total ARP Request traffic generated from a specific MAC address  |
| ARPpb  | Total ARP Probe traffic generated from a specific MAC address  |
| ARPan  | Total ARP Announcement traffic generated from a specific MAC address  |
| ARPgr  | Total ARP Gratitous traffic generated from a specific MAC address  |
| IPF  | Total ARP Request generated from a specific MAC address to an IP address which exists   |
| IP_ICMP  | Total IP ICMP traffic generated from a specific MAC address  |
| IP_UDP  | Total IP UDP traffic generated from a specific MAC address  |
| IP_TCP  | Total IP TCP traffic generated from a specific MAC address  |
| IP_RESTO  | Other traffic generated from a specific MAC address  |
| IPv6  | Total IPv6 traffic generated from a specific MAC address  |
| ETH_RESTO  | Total ETHERNET traffic generated from a specific MAC address  |
| ARP_noIP  | Total ARP Request generated from a specific MAC address to an IP address which does NOT exist   |

Once the features were determined for machine learning, the next step is to generate the dataset. This is typically implemented in stages based first on an attack-free netwok and then a number of attacks until all the classes that need to be considered are fully covered by the dataset. The final dataset will cover distinct attackt types and attack-free circumstances. 
