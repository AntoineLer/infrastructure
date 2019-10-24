
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sys

'''Global variables about the file to read.'''
name = 'netflow.csv_639fee2103e6c2d3180d_.gz'
nrows = 92507632
compr = 'gzip'
dtype = {'td':'float32',    #time duration
         'ipkt':'uint32',   #nbr of bytes
         'ibyt':'uint32',   #nbr of packets
         'sp':'uint32',     #source port
         'dp':'uint32',     #destination port
         'pr':'object',     #protocol
         'sa':'object'}     #source IP address

def CDF(data, comp=False):
    """Function computing the (complementary) cumulative distribution
       fonction of a pandas.Series of numerical values.

    Parameters:
    data (pandas.Series):   serie of n numerical values
    comp (bool):            by default = False, set to True
                            to compute the complementary CDF

    Returns:
    x, y (numpy.array):     shape (n,1), used to plot the (C)CDF
                            x: the different values of the series in ascending order
                            y: their probability such that p(X <= x)

    """

    len_data = data.shape[0]
    x, counts = np.unique(data, return_counts=True)
    y = np.cumsum(counts) / len_data
    if comp:
        '''Replace y by its complementary values'''
        y = 1 - y
    return x, y

def plot(x, y, xlabel, ylabel, name_fig, xlog=False, ylog=False):
    """Function used to generate a plot and save it in '.pdf' format

    Parameters:
    x, y (numpy.array):         shape (n, 1), values to plot as y = f(x)
    xlabel, ylabel (string):    description of x and y axis
    name_fig (string):          saved file name = "<name_fig>.pdf"
    xlog, ylog (bool):          by default = False, set to True to use
                                x/y logarithmic scale

    Returns:
    nothing but generates a pdt file
    """
    plt.figure()
    plt.plot(x, y)
    if xlog:
        plt.xscale('log')
    if ylog:
        plt.yscale('log')
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.savefig(name_fig + '.pdf')

def first_question():
    """Function used to answer the question 1:
        - CDF of packet size across all traffic
        - average packet size

    Parameters:
    None

    Returns:
    Nothing but print on the terminal the avg pkt size
    and generate a pdf file.
    """

    print("Question 1...\n")

    '''Read the ipkt and ibyt field of the data file'''
    data = pd.read_csv(
        name,
        nrows=nrows,
        usecols=[
            'ipkt',
            'ibyt'],
        dtype=dtype,
        compression=compr)

    '''Compute the packet size'''
    packet_size = data.ibyt / data.ipkt
    data = None

    '''Compute and plot the CDF of pkt size'''
    x, y = CDF(packet_size)
    plot(x, y, '$Packet\ size\ (byte)$', '$Probability$', 'CDF_size_pkt')

    '''Print the average packet size'''
    print('average packet size: %.2f\n' % (np.mean(packet_size)))

    print("End of Question 1!\n")


def second_question():
    """Function used to answer the question 2:
        - CCDF of flow durations and flow sizes

    Parameters:
    None

    Returns:
    Nothing but generates 6 pdf files
    """

    print("Question 2...\n")

    '''Read the ipkt, ibyt and td field of the data file'''
    data = pd.read_csv(
        name,
        nrows=nrows,
        usecols=[
            'ipkt',
            'ibyt',
            'td'],
        dtype=dtype,
        compression=compr)

    '''Compute and generate plots of CCDF'''
    field = {'td': '$flow\ duration\ (s)$',
             'ipkt': '$size\ of\ flow\ (packet)$',
             'ibyt': '$size\ of\ flow\ (bytes)$'}
    for key, value in field.items():
        x, y = CDF(data[key], True)
        #linear scale
        plot(x, y, value, '$Probability$', 'ccdf_linear_' + key)
        #logarithmic scale
        plot(x, y, value, '$Probability$', 'ccdf_log_' + key, True, True)
    print("End of Question 2!\n")


def third_question():
    """Function used to answer the question 3:
        - Top-ten list of TCP/UDP sender/reveiver port and traffic volume

    Parameters:
    None

    Returns:
    Nothing but print on the terminal the tables
    """

    print("Question 3...\n")

    '''Read the sp, dp, pr and ibyt field of the data file'''
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

    '''Compute the total number of bytes'''
    number_of_byte = netf_trace.ibyt.sum()

    '''Generate TCP/UDP source/destionation port tables for each pair'''
    port_type = {'Source Port':'sp', 'Destination Port':'dp'}
    for ptc in ['TCP', 'UDP']:
        for port_type_name, p_type in port_type.items():
            print(ptc + ' ' + port_type_name + ':\n')

            '''Top-ten most used port'''
            top_ten_port = netf_trace[netf_trace.pr ==
                        ptc][p_type].value_counts().head(10)

            '''Get corresponding traffic volume'''
            top_ten_port = netf_trace[netf_trace[p_type].isin(top_ten_port.index)].loc[
                :, [p_type, 'ibyt']].groupby(p_type).sum()
            top_ten_port['Traffic Volume'] = top_ten_port.ibyt / number_of_byte
            top_ten_port.index.name = port_type_name
            top_ten_port = top_ten_port.sort_values(by = 'Traffic Volume', ascending=False)

            '''Print the table'''
            print(top_ten_port, '\n')

    print("End of Question 3!\n")


def fourth_question():
    """Function used to answer the question 4:

    Parameters:
    None

    Returns:
    Nothing but print on the terminal
    """
    print("Question 4...\n")

    '''Read the sa and ibyt field of the data file'''
    netf_trace = pd.read_csv(
        name,
        nrows=nrows,
        usecols=[
            'sa',
            'ibyt'],
        dtype=dtype,
        compression=compr)

    '''Compute the total number of bytes'''
    total_byte = netf_trace.ibyt.sum()

    '''Exclude the IPv6 addresses'''
    excluded_data = netf_trace[netf_trace['sa'].str.contains(":")]
    print(
        "Percentage of traffic excluded :",
        excluded_data.ibyt.sum() / total_byte,
        "\n")
    netf_trace.drop(excluded_data.index, axis=0, inplace=True)
    excluded_data = None

    '''Create IP prefix (sa) with /24 mask'''
    #inversing (Regex found on StackOverFlow)
    netf_trace['Prefix'] = netf_trace.sa.str.replace(r'\.\d+$', '.0/24')

    '''Count the number of time a prefix /24 is used'''
    netf_trace['Number_of_times_used'] = 1
    netf_trace = netf_trace.loc[:, :].groupby('Prefix').sum()
    netf_trace["Traffic Volume"] = netf_trace.ibyt / total_byte
    netf_trace.drop('ibyt', axis=1, inplace=True)

    '''Print most popular source IP prefix'''
    most_popular_percentage = [(0.001, "0.1% of source IP prefix :"), (0.01,"1% of source IP prefix:"), (0.1, "10% of source IP prefix:")]
    most_popular = [(round(Pb[0]*netf_trace['Number_of_times_used'].shape[0]), Pb[1]) for Pb in most_popular_percentage]
    for popular in most_popular:
        print("Fraction of the volume from the most popular " + popular[1], netf_trace.nlargest(popular[0], 'Number_of_times_used')['Traffic Volume'].sum(), "\n")

    print(netf_trace.nlargest(10, 'Traffic Volume'))

    print("End of Question 4!\n")

def fifth_question():
    """Function used to answer the question 5:

    Parameters:
    None

    Returns:
    Nothing but print on the terminal
    """
    print("Question 5...\n")
    nrows = 2*(10**7)
    netf_trace = pd.read_csv(
        name,
        nrows=nrows,
        usecols=[
            'sa',
            'da',
            'ipkt',
            'ibyt'],
        dtype=dtype,
        compression=compr)

    print("Finished reading files\n")

    #Total number of ipkt
    total_ipkt = netf_trace.ipkt.sum()
    #Total number ibyt
    total_ibyt = netf_trace.ibyt.sum()

    #Excluded Data are IPv6
    excluded_data = netf_trace[netf_trace['sa'].str.contains(":")]
    netf_trace.drop(excluded_data.index, axis=0, inplace=True)
    excluded_data = None

    #IP Prefix sa
    netf_trace['sa'] = netf_trace.sa.str.replace(r'\.\d+$', '.0/24')
    #IP prefix da
    netf_trace['da'] = netf_trace.da.str.replace(r'\.\d+$', '.0/24')
    netf_trace['Number_of_times_used'] = 1

    #Source
    print("Number of times the popular sources addresses appear:")
    source = netf_trace.groupby('sa').sum().nlargest(10, 'Number_of_times_used')
    source.ipkt = source.ipkt / total_ipkt
    source.ibyt = source.ibyt / total_ibyt
    print(source)
    
    #Destination
    print("Number of times the popular destinations addresses appear:")
    dest = netf_trace.groupby('da').sum().nlargest(10, 'Number_of_times_used')
    dest.ipkt = dest.ipkt / total_ipkt
    dest.ibyt = dest.ibyt / total_ibyt
    print(dest)

    print("End of Question 5!\n")


def main(argv):
    if argv[0] == "1":
        first_question()
    elif argv[0] == "2":
        second_question()
    elif argv[0] == "3":
        third_question()
    elif argv[0] == "4":
        fourth_question()
    elif argv[0] == "5":
        fifth_question()
    else:
        print("Choose only one question between 1 and 5 only!")

if __name__ == "__main__":
    # execute only if run as a script
    main(sys.argv[1:])
