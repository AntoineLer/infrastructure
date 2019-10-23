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

#/mnt/c/Users/Antoine/OneDrive/Documents/Antoine/ULG/MASTER\ 1/1er\ Quadri/Network\ infrastructures/Assignments/First_assignment/
def CDF(data, comp=False):

    # sort the data
    len_data = data.shape[0]
    if comp:  # reverse order
        x = np.sort(data)[::-1]
    else:
        x = np.sort(data)
    y = 1. * np.arange(len_data) / (len_data - 1)

    return x, y


def CDF_test(data, comp=False):
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
    nrows = 92507632
    # nrows = 10**7
    data = pd.read_csv(
        "netflow.csv_639fee2103e6c2d3180d_.gz",
        nrows=nrows,
        usecols=[
            'ipkt',
            'ibyt'],
        compression='gzip')
    packet_size = data.ibyt / data.ipkt
    print("Total number of byte", data.ibyt.sum(), "\n")
    data = None
    x, y = CDF_test(packet_size)

    # plot the cumulative distribution function
    plot(x, y, '$Packet\ size\ (byte)$', '$Probability$', 'CDF_size_pkt')

    # average packet size
    print('average packet size: %.2f\n' % (np.mean(packet_size)))
    print("End of Question 1!\n")


def second_question():
    print("Question 2...\n")
    nrows = 92507632
    # nrows = 10**7
    data = pd.read_csv(
        "netflow.csv_639fee2103e6c2d3180d_.gz",
        nrows=nrows,
        usecols=[
            'ipkt',
            'ibyt',
            'td'],
        compression='gzip')
    field = {'td': '$flow\ duration\ (s?)$',
             'ipkt': '$size\ of\ flow\ (packet)$',
             'ibyt': '$size\ of\ flow\ (bytes)$'}
    for key, value in field.items():
        x, y = CDF_test(data[key], True)
        # plot linear scale
        plot(x, y, value, '$p$', 'ccdf_linear_' + key)
        plot(x, y, value, '$p$', 'ccdf_log_' + key, True, False)
    print("End of Question 2!\n")


def third_question():
    print("Question 3...\n")
    nrows = 92507632
    # nrows = 10**7
    netf_trace = pd.read_csv(
        "netflow.csv_639fee2103e6c2d3180d_.gz",
        nrows=nrows,
        usecols=[
            'sp',
            'dp',
            'pr',
            'ibyt'],
        compression='gzip')
    number_of_byte = netf_trace.ibyt.sum()
    print("Total number of byte", number_of_byte)
    # TCP

    # Source port in TCP
    print("TCP Source Port:\n")
    tcp_sp = netf_trace[netf_trace.pr ==
                        'TCP'].sp.value_counts().head(10)
    tcp_sp = netf_trace[netf_trace.sp.isin(tcp_sp.index)].loc[
        :, ['sp', 'ibyt']].groupby('sp').sum()
    tcp_sp['Volume Traffic'] = tcp_sp.ibyt / number_of_byte
    tcp_sp.index.name = "Source_port"
    print(tcp_sp, "\n")

    # Destination Port in TCP
    print("TCP Destination Port:\n")
    tcp_dp = netf_trace[netf_trace.pr ==
                        'TCP'].dp.value_counts().head(10)
    tcp_dp = netf_trace[netf_trace.dp.isin(tcp_dp.index)].loc[
        :, ['dp', 'ibyt']].groupby('dp').sum()
    tcp_dp['Volume Traffic'] = tcp_dp.ibyt / number_of_byte
    tcp_dp.index.name = "Dest_port"
    print(tcp_dp, "\n")
    # END of TCP

    # UDP

    # Source port in UDP
    print("UDP Source Port:\n")
    udp_sp = netf_trace[netf_trace.pr ==
                        'UDP'].sp.value_counts().head(10)
    udp_sp = netf_trace[netf_trace.sp.isin(udp_sp.index)].loc[
        :, ['sp', 'ibyt']].groupby('sp').sum()
    udp_sp['Volume Traffic'] = udp_sp.ibyt / number_of_byte
    udp_sp.index.name = "Source_port"
    print(udp_sp, "\n")

    # Destination Port in TCP
    print("UDP Destination Port:\n")
    udp_dp = netf_trace[netf_trace.pr ==
                        'UDP'].dp.value_counts().head(10)
    udp_dp = netf_trace[netf_trace.dp.isin(udp_dp.index)].loc[
        :, ['dp', 'ibyt']].groupby('dp').sum()
    udp_dp['Volume Traffic'] = udp_dp.ibyt / number_of_byte
    udp_dp.index.name = "Dest_port"
    print(udp_dp, "\n")
    # END of UDP

    print("End of Question 3!\n")


def fourth_question():
    print("Question 4...\n")
    #nrows = 92507632
    nrows = 10**5
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
        excluded_data.ibyt.sum() /
        total_byte,
        "\n")
    excluded_data = None

    # EXCLUDING IPv6 from data
    netf_trace = netf_trace[(netf_trace['sa'].str.contains(":") == False)]

    # SORTING Source IP
    # CREATING IP PREFIX (SOURCE ADDRESS)
    netf_trace[['First', 'Second', 'Third', 'Fourth']
               ] = netf_trace.sa.str.split(".", expand=True)
    netf_trace.drop('Fourth', axis=1, inplace=True)
    netf_trace['Prefix'] = netf_trace.First + \
        '.' + netf_trace.Second + '.' + netf_trace.Third + '.0/24'
    netf_trace.drop(['First', 'Second', 'Third'],
                    axis=1, inplace=True)

    # Counting the number of times a prefix is used
    counter = netf_trace.Prefix.value_counts()
    netf_trace = netf_trace[
        netf_trace.Prefix.isin(counter.index)].loc[:, ['Prefix', 'ibyt']].groupby('Prefix').sum()
    netf_trace['Number_of_times_used'] = counter
    netf_trace['Pr_utilization'] = netf_trace.Number_of_times_used / \
        netf_trace.Number_of_times_used.sum()

    # Sorting prefix by the number of times used
    netf_trace = netf_trace.sort_values(by='Number_of_times_used')
    netf_trace["Volume Traffic"] = netf_trace.ibyt / total_byte
    netf_trace.drop('ibyt', axis=1, inplace=True)
    print(netf_trace)
    most_popular = [0.1 / 100, 1 / 100, 10 / 100]
    length_popular = [np.round(num * len(netf_trace)) for num in most_popular]
    print(length_popular)
    print("End of Question 4!\n")


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
        return
    else:
        print("Choose one question between 1 and 5 only!")

if __name__ == "__main__":
    # execute only if run as a script
    main(sys.argv[1:])
