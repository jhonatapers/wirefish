class Packet:
    
    def __init__(self, index : int, data : bytes):
        self.data = data
        self.index = index