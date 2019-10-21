import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


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


def first_question(data):
    packet_size = data.ibyt / data.ipkt
    x, y = CDF_test(packet_size)

    # plot the cumulative distribution function
    plot(x, y, '$Packet\ size\ (byte)$', '$Probability$', 'CDFipkt')

    # average packet size
    print('average packet size: %.2f' % (np.mean(packet_size)))


def second_question(data):
    field = {'td': '$flow\ duration\ (s?)$',
             'ipkt': '$size\ of\ flow\ (packet)$',
             'ibyt': '$size\ of\ flow\ (bytes)$'}
    for key, value in field.items():
        x, y = CDF(data[key], True)
        # plot linear scale
        plot(x, y, value, '$p$', 'ccdf_linear_' + key)
        plot(x, y, value, '$p$', 'ccdf_log_' + key, True, True)


def third_question(data):
    tcp_data = netf_trace.loc[
        (netf_trace['pr'] == 'TCP'), [
            'sp', 'dp', 'ibyt']]
    # print(tcp_data[tcp_data['sp'].value_counts().index])
    print(tcp_data['sp'].value_counts().head(10))
    print(tcp_data['dp'].value_counts().head(10))
    udp_data = netf_trace.loc[(netf_trace['pr'] == 'UDP'), ['sp', 'dp']]
    print(udp_data['sp'].value_counts().head(10))
    print(udp_data['dp'].value_counts().head(10))

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


def main():
    netf_trace = pd.read_csv(
        "netflow.csv_639fee2103e6c2d3180d_.gz",
        nrows=92507632,
        usecols=[
            'ipkt',
            'ibyt'],
        compression='gzip')
    # print(netf_trace.ibyt / netf_trace.ipkt)
    #-------------question 1-------------

    # retreive the packet size from the dataframe
    first_question(netf_trace)
    netf_trace = None
    #-------------question 2-------------

    # retreive the flow duration and the flow sizes from the dataframe
    netf_trace = pd.read_csv(
        "netflow.csv_639fee2103e6c2d3180d_.gz",
        nrows=92507632,
        usecols=[
            'ipkt',
            'ibyt',
            'td'],
        compression='gzip')
    # and compute their CCDF
    second_question(netf_trace)

    #-------------question 3-------------

    # filter TCP/UDP flows


if __name__ == "__main__":
    # execute only if run as a script
    main()
