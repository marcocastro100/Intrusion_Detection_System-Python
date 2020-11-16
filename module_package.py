class Processor_package:
    #receives a package (dump line) as parameter, but in the case that the instance has been made just to assemble various lines of packages, then no parameter should be given, and a package will be made with zero's; (this way just to take the assemble_packages out of the common.py
    def __init__(self,package=[0]*16):
        try:
            self.relative_time = float(package[2])
            self.protocol_type = int(package[3])
            self.service = str(package[4])
            self.flag = str(package[5])
            self.length = int(package[7])
            self.ip_flag = str(package[8])
            self.ip_src = str(package[14])
            self.ip_dst = str(package[15])
            if(self.protocol_type == 6):
                self.stream = int(package[0]);
                self.src_port = int(package[10]);
                self.dst_port = int(package[11]);
                self.window_size = int(package[9]);
                self.urgent = int(package[6]);
            elif(self.protocol_type == 17 or self.protocol_type == 1):
                self.stream = int(package[1]);
                self.src_port = int(package[12]);
                self.dst_port = int(package[13]);
                self.window_size = int(0);
                self.urgent = int(0);
        except:
            print('Error:',package);
            
            
    def Assemble_packages(self,file_lines):
        assembled_packages = []
        raw_packages = [aux.split(',') for aux in file_lines] #Stores the pkg attributes (that are divided by a ',')
        for single_package in range(0,len(raw_packages)): #len(lines) == quantity of packages readed from file_lines
            if(len(raw_packages[single_package]) == 16): #checks if the package was captured fully or parcialy (try-catch)
                if(raw_packages[single_package][3] == '6' or raw_packages[single_package][3] == '17' or raw_packages[single_package][3] == '1'):#tcp or udp (try-catch)
                    if(raw_packages[single_package][0] != '' or raw_packages[single_package][1] != ''): #if has a stream number
                        obj_package = Processor_package(raw_packages[single_package]) #Instatiate the package
                        assembled_packages.append(obj_package);
            else:
                print('smaller package size:',len(raw_packages[single_package]));
        return(assembled_packages);


#=================================================================================