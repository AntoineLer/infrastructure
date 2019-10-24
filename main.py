import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sys

# Indices used in nfdump 1.6
# ts,te,td  time records: t-start, t-end, duration
# sa,da     src dst address
# sp,dp     src, dst port
# pr        protocol
# flg       flags
# fwd       forwarding status
# stos      src tos
# ipkt,ibyt input packets/bytes
# opkt,obyt output packets, bytes
# in,out    input/output interface SNMP number
# sas,das   src, dst AS
# smk,dmk   src, dst mask
# dtos      dst tos
# dir       direction
# nh,nhb    nethop IP address, bgp next hop IP
# svln,dvln src, dst vlan id
# ismc,odmc input src, output dst MAC
# idmc,osmc input dst, output src MAC
# mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10 MPLS label 1-10
# cl,sl,al  client server application latency (nprobe)
# ra        router IP
# eng       router engine type/id
# exid      exporter SysID

# parameter about the file to read
name = 'netflow.csv_639fee2103e6c2d3180d_.gz'
nrows = 92507632
compr = 'gzip'
dtype = {'td': 'float32',
         'ipkt': 'uint32',
         'ibyt': 'uint32',
         'sp': 'uint32',
         'dp': 'uint32',
         'pr': 'object',
         'sa': 'object'}


def CDF(data, comp=False):
    # sort the data
    len_data = data.shape[0]
    x, counts = np.unique(data, return_counts=True)
    y = np.cumsum(counts) / len_data
    if comp:  # reverse order
        y = 1 - y
    return x, y


def plot(x, y, xlabel, ylabel, name_fig, xlog=False, ylog=False):

    plt.figure()
    plt.plot(x, y)
    if xlog:
        plt.xscale('log')
    if ylog:
        plt.yscale('log')
    # plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.savefig(name_fig + '.pdf')


def first_question():
    print("Question 1...\n")
    data = pd.read_csv(
        name,
        nrows=nrows,
        usecols=[
            'ipkt',
            'ibyt'],
        dtype=dtype,
        compression=compr)
    packet_size = data.ibyt / data.ipkt
    print("Total number of byte", data.ibyt.sum(), "\n")
    data = None
    x, y = CDF(packet_size)

    # plot the cumulative distribution function
    plot(x, y, '$Packet\ size\ (byte)$', '$Probability$', 'CDF_size_pkt')

    # average packet size
    print('average packet size: %.2f\n' % (np.mean(packet_size)))
    print("End of Question 1!\n")


def second_question():
    print("Question 2...\n")
    data = pd.read_csv(
        name,
        nrows=nrows,
        usecols=[
            'ipkt',
            'ibyt',
            'td'],
        dtype=dtype,
        compression=compr)
    field = {'td': '$flow\ duration\ (s?)$',
             'ipkt': '$size\ of\ flow\ (packet)$',
             'ibyt': '$size\ of\ flow\ (bytes)$'}
    for key, value in field.items():
        x, y = CDF(data[key], True)
        # plot linear scale
        plot(x, y, value, '$p$', 'ccdf_linear_' + key)
        plot(x, y, value, '$p$', 'ccdf_log_' + key, True, True)
    print("End of Question 2!\n")


def third_question():
    print("Question 3...\n")
    netf_trace = pd.read_csv(
        name,
        nrows=nrows,
        usecols=[
            'sp',
            'dp',
            'pr',
            'ibyt'],
        dtype=dtype,
        compression=compr)
    number_of_byte = netf_trace.ibyt.sum()
    print("Total number of byte", number_of_byte)
    # for TCP/UDP and Source/Destination port, extract top ten port + traffic
    # volume
    port_type = {'Source Port': 'sp', 'Destination Port': 'dp'}
    for ptc in ['TCP', 'UDP']:
        for port_type_name, p_type in port_type.items():
            print(ptc + ' ' + port_type_name + ':\n')
            top_ten_port = netf_trace[netf_trace.pr ==
                                      ptc][p_type].value_counts().head(10)
            top_ten_port = netf_trace[netf_trace[p_type].isin(top_ten_port.index)].loc[
                :, [p_type, 'ibyt']].groupby(p_type).sum()
            top_ten_port['Traffic Volume'] = top_ten_port.ibyt / number_of_byte
            top_ten_port.index.name = port_type_name
            print(top_ten_port, '\n')

    print("End of Question 3!\n")


def fourth_question():
    print("Question 4...\n")
    nrows = 10**7
    netf_trace = pd.read_csv(
        "netflow.csv_639fee2103e6c2d3180d_.gz",
        nrows=nrows,
        usecols=[
            'sa',
            'ibyt'],
        compression='gzip')

    # TOTAL Byte
    total_byte = netf_trace.ibyt.sum()

    # EXCLUDED DATA == IPv6
    excluded_data = netf_trace[netf_trace['sa'].str.contains(":")]
    print(
        "Percentage of traffic excluded :",
        excluded_data.ibyt.sum() / total_byte,
        "\n")
    excluded_data = None
    # EXCLUDING IPv6 from data
    netf_trace = netf_trace[(netf_trace['sa'].str.contains(":") == False)]

    # CREATING IP PREFIX (SOURCE ADDRESS) with /24 MASK
    IP_divided = netf_trace.sa.str.split(".", expand=True)
    netf_trace['Prefix'] = IP_divided[0] + '.' + IP_divided[1] + '.' + IP_divided[3] + '.0/24'
    IP_divided = None

    # COUNTING THE NUMBER OF TIMES A PREFIX WITH /24 MASK IS USED
    netf_trace['Number_of_times_used'] = 1
    netf_trace = netf_trace.loc[:, :].groupby('Prefix').sum()
    netf_trace['Pr_utilization'] = netf_trace.Number_of_times_used / netf_trace.Number_of_times_used.sum()
    netf_trace["Traffic Volume"] = netf_trace.ibyt / total_byte
    netf_trace.drop('ibyt', axis=1, inplace=True)

    # SORTING PREFIX BY THE NUMER OF TIMES USED
    netf_trace = netf_trace.sort_values(by='Number_of_times_used', ascending=False)
    #print(netf_trace)

    ####### ON DOIT DECIDER DE QUEL MASK GARDER ? #######

    # CREATING IP PREFIX (SOURCE ADDRESS) with /16 MASK
    """mask = netf_trace
    mask['Prefix'] = counter.index
    mask.index = pd.Series(range(0, len(netf_trace)))
    mask[['First', 'Second', 'Third', 'Fourth']] = mask.Prefix.str.split(".", expand=True)
    mask['Prefix'] = netf_trace.First + '.' + netf_trace.Second + '.0.0/16'
    mask.drop(['First', 'Second', 'Third', 'Fourth'], axis=1, inplace=True)
    counter = netf_trace.Prefix.value_counts()
    mask = mask[mask.Prefix.isin(counter.index)].groupby('Prefix').sum().sort_values(by='Number_of_times_used')
    print(mask)"""


    most_popular_percentage = [(0.001, "0.1% of source IP prefixe:"), (0.01,"1% of source IP prefixe:"), (0.1, "10% of source IP prefixe:")]
    most_popular = [(round(Pb[0]*netf_trace['Number_of_times_used'].shape[0]), Pb[1]) for Pb in most_popular_percentage]
    for popular in most_popular:
        print("Fraction of the volume from the most popular " + popular[1], netf_trace.head(popular[0])['Traffic Volume'].sum(), "\n")
    ###### TO CONTINUE ######
    print("End of Question 4!\n")

def fifth_question():
    print("Question 5...\n")
    nrows = 10**6
    netf_trace = pd.read_csv(
        "netflow.csv_639fee2103e6c2d3180d_.gz",
        nrows=nrows,
        usecols=[
            'sa',
            'da',
            'ibyt'],
        compression='gzip')
    IP_MONTEF ="139.165."
    IP_RUN = "139.165."

    BY_MONTEF = netf_trace[netf_trace.sa.str.contains(IP_MONTEF, na=False)]
    TO_MONTEF = netf_trace[netf_trace.da.str.contains(IP_MONTEF, na=False)]
    print(BY_MONTEF, "\n", TO_MONTEF)

    print("End of Question 5!\n")

def main(argv):
    if argv[0] == "1":
        #-------------question 1-------------

        # retreive the packet size from the dataframe

        first_question()
    elif argv[0] == "2":
        #-------------question 2-------------

        # retreive the flow duration and the flow sizes from the dataframe
        # and compute their CCDF
        second_question()
    elif argv[0] == "3":
        #-------------question 3-------------

        # filter TCP/UDP flows
        third_question()
    elif argv[0] == "4":
        fourth_question()
    elif argv[0] == "5":
        fifth_question()
    else:
        print("Choose one question between 1 and 5 only!")

if __name__ == "__main__":
    # execute only if run as a script
    main(sys.argv[1:])
