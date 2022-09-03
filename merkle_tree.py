import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


# A class for the nodes of the tree
class Node:
    """
    init:
    we save the left son, the right son, the father and the data of the node.
    """
    def __init__(self, data):
        self.right = None
        self.left = None
        self.father = None
        self.data = data

    """
    set_right:
    setting the right child
    """
    def set_right(self, node):
        self.right = node
        node.set_father(self)

    """
    set_left:
    setting the left child
    """
    def set_left(self, node):
        self.left = node
        node.set_father(self)

    """
    set_father:
    setting the father
    """
    def set_father(self, node):
        self.father = node

    """
    get_right:
    getting the right child
    """
    def get_right(self):
        return self.right

    """
    get_left:
    getting the left child
    """
    def get_left(self):
        return self.left

    """
    get_father:
    getting the father
    """
    def get_father(self):
        return self.father

    """
    set_data:
    sets the data of this node
    """
    def set_data(self, data):
        self.data = data

    """
    get_data:
    gets the data of this node
    """
    def get_data(self):
        return self.data

    """
    checks if this node is the left son of his father.
    """
    def is_left_son(self):
        if self.father is None:
            return False
        left = self.get_father().get_left()
        if left is None:
            return False
        return left is self


# A class for the normal Merkle Tree
class MerkleTree:

    """
    init:
    leafs - the leafs of the tree
    """
    def __init__(self):
        self.leafs = []
        self.nodes = None
        self.root = None

    """
    insert_leaf:
    data - the data we insert to the tree
    """
    def insert_leaf(self, data):
        # hashing the data in sha256
        new_leaf = hashlib.sha256(data.encode('utf-8')).hexdigest()
        # putting the has result in the tree
        self.leafs.append(new_leaf)
        self.nodes = None

    """
    create_new_tree:
    calculate the current tree given the leafs of this Merkle Tree.
    """
    def create_new_tree(self):
        self.nodes = []
        # if there are no leafs, stop
        if len(self.leafs) == 0:
            return
        for leaf in self.leafs:
            self.nodes.append(Node(leaf))
        # saving a copy of the nodes
        temp1 = self.nodes.copy()
        temp2 = []
        # while the length of temp1 is not 1, move one step towards the root
        while len(temp1) != 1:
            # from 0 to length of temp1 (rounding down if odd)
            for i in range(0, len(temp1) - len(temp1) % 2, 2):
                # get the value of the father
                new_father = Node((hashlib.sha256((temp1[i].get_data() + temp1[i + 1].get_data()).encode('utf-8'))).hexdigest())
                # set the children of the father
                new_father.set_left(temp1[i])
                new_father.set_right(temp1[i + 1])
                # append the father inside the list of nodes
                temp2.append(new_father)
                # sets this father as the father of his children
                temp1[i].set_father(new_father)
                temp1[i+1].set_father(new_father)
            # in this case we do not hash one node alone, so we only add it to temp2
            if len(temp1) % 2 == 1:
                temp2.append(temp1[len(temp1) - 1])
            # reset values, temp1 as the new set of nodes(the fathers), and temp2 as a new list
            temp1 = temp2.copy()
            temp2 = []
        # save the value of the root for 'calc_root' later
        self.root = temp1[0]

    """
    calc_root:
    calculating the root of the tree. 
    """
    def calc_root(self):
        # if there are no leafs, there is no root, return None
        if len(self.leafs) == 0:
            return None
        # if the nodes are None, we did not update the tree from the recent leaf insert
        if self.nodes is None:
            self.create_new_tree()
        return self.root.get_data()

    """
    proof_of_inc:
    creating a proof for the leaf on index 'index'.
    """
    def proof_of_inc(self, index):
        # if there are no leafs, there is no proof, return None
        if len(self.leafs) == 0:
            return None
        # if the nodes are None, we did not update the tree from the recent leaf insert
        if self.nodes is None:
            self.create_new_tree()
        proof = ""
        # setting the current node as the node we want to create the proof on
        current_node = self.nodes[index]
        # going up every step until we reach the root
        while current_node.get_father() is not None:
            # will be True if the current node is the left son of his father
            is_left_son = current_node.is_left_son()
            # if it is the left son, put the right son of the father in the proof(with '1' indicator)
            if is_left_son:
                current_node = current_node.get_father()
                proof += " " + "1" + current_node.get_right().get_data()
            # if it is the right son, put the left son of the father in the proof(with '0' indicator)
            else:
                current_node = current_node.get_father()
                proof += " " + "0" + current_node.get_left().get_data()
        # return the proof with the value of the root first.
        return self.root.get_data() + proof

    """
    check_proof:
    receives a proof and data, and check if the proof is good
    for the current tree and the data
    """
    def check_proof(self, data, proof):
        # if there are no leafs in the tree, data is also not in the tree
        if len(self.leafs) == 0:
            return None
        # splitting the proof (splitting root and proof)
        split_proof = proof.split(' ')
        # checking if the root of the proof is the same as the current root, if not, we don't need to continue
        root = split_proof[0]
        # setting the proof array
        proof_arr = split_proof[1:]
        # adding the data to the proof
        proof_arr.insert(0, '0' + hashlib.sha256(data.encode('utf-8')).hexdigest())
        # going through the proof
        while len(proof_arr) != 1:
            # if the first index is 0, the second component is the left child, meaning we hash it first
            if proof_arr[1][0] == '0':
                proof_arr.insert(0, '0' + hashlib.sha256((proof_arr[1][1:] + proof_arr[0][1:]).encode('utf-8')).hexdigest())
            # if the first index is 1, the second component is the right child, meaning we hash it second
            elif proof_arr[1][0] == '1':
                proof_arr.insert(0, '0' + hashlib.sha256((proof_arr[0][1:] + proof_arr[1][1:]).encode('utf-8')).hexdigest())
            # else, the proof is not in the correct format, return None
            else:
                return None
            # pop the two components we now used
            proof_arr.pop(1)
            proof_arr.pop(1)
        # we reached to a root, check if the root we received is the same as the real root
        if proof_arr[0][1:] == root:
            return True
        else:
            return False

    """
    create_sk_pk:
    simply creates a secret key and a public key
    """
    def create_sk_pk(self):
        # generating private key
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend())
        # creating a pem for the private key
        pem_sk = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption())
        # getting public key
        public_key = private_key.public_key()
        # creating a pem for the public key
        pem_pk = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # adding the two pems together
        pem = pem_sk + b'\n' + pem_pk
        # return the two keys in the format
        return pem.decode()

    """
    signature:
    signing the root using the private key
    """
    def signature(self, private_key_str):
        # getting the pem from the private key string
        pem = private_key_str.encode()
        # getting the key from the pem
        private_key = load_pem_private_key(pem, password=None)
        # signing the root using the private key
        signature = private_key.sign(self.calc_root().encode(),
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                 salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
        # returning the signature in base 64
        return base64.b64encode(signature).decode()

    """
    verify_signature:
    getting a public key, a signature and a text, and verifying the signature
    of the text using the public key.
    """
    def verify_signature(self, public_key_str, signature, text):
        # getting the pem from the public key
        pem = public_key_str.encode()
        # getting the public key from the pem
        public_key = load_pem_public_key(pem)
        # verifying the signature. if we get an exception, it means the verification failed, and we return false.
        try:
            public_key.verify(base64.decodebytes(signature.encode()), text.encode(), padding.PSS(
                              mgf=padding.MGF1(hashes.SHA256()),
                              salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except:
            return False


# A class for the Sparse Merkle Tree
class SparseMerkleTree:
    """
    init:
    saving the length of the sparse merkle tree (for this exercise: 256),
    the default values that will be set though 'calculate_defaults':
        * the value of default[i] will be the value of a node in height i,
          if every leaf below this node is 0
    and a root of the tree.
    """
    def __init__(self):
        self.length = 256
        self.defaults = [0]*(self.length+1)
        self.calculate_defaults()
        self.root = None

    """
    calculate_defaults:
    calculate the defaults (explained in init notes)
    """
    def calculate_defaults(self):
        first = '0'
        second = '0'
        self.defaults[0] = '0'
        # starting with two zeros, calculate each default value according to his height
        # in the tree, and put in self.default
        for i in range(self.length):
            self.defaults[i+1] = hashlib.sha256((first+second).encode('utf-8')).hexdigest()
            first = self.defaults[i+1]
            second = self.defaults[i+1]

    """
    insert_leaf:
    inserting a leaf to the tree (meaning we change the leaf of this digest to be 1)
    """
    def insert_leaf(self, digest):
        # getting the digest from hex to binary
        digest = hex2binary(digest)
        # the depth of the tree, starting with the depth of root, which is the length of the tree
        depth = self.length
        # if the root is none, start from the None Node
        if self.root is None:
            self.root = Node(None)
        # starting from root
        current_node = self.root
        # for every digit in the digest, go right if it is 1 and left it is 0
        for digit in digest:
            # we are going down, so decrease depth
            depth -= 1
            if digit == '0':
                if current_node.get_left() is None:
                    current_node.set_left(Node(None))
                current_node = current_node.get_left()
            elif digit == '1':
                if current_node.get_right() is None:
                    current_node.set_right(Node(None))
                current_node = current_node.get_right()
            else:
                return None
        # we reached the bottom, the location of the node 1
        current_node.set_data('1')
        # we now go up until we reach the root, and update each node's value
        while current_node.father is not None:
            current_node = current_node.get_father()
            right_data = ""
            left_data = ""
            # setting the right value
            if current_node.get_right() is None:
                right_data = self.defaults[depth]
            else:
                right_data = current_node.get_right().get_data()
            # setting the left value
            if current_node.get_left() is None:
                left_data = self.defaults[depth]
            else:
                left_data = current_node.get_left().get_data()
            # update the value of this node to be the hash of his two children
            current_node.set_data(hashlib.sha256((left_data + right_data).encode('utf-8')).hexdigest())
            # go up the tree
            depth += 1

    """
    calc_root:
    calculating the root of the tree
    """
    def calc_root(self):
        # if the root is none, give the default value of the root
        if self.root is None:
            return self.defaults[self.length]
        # return the value of the root
        return self.root.get_data()

    """
    proof_of_inc:
    creating a proof of inclusion for a given digest
    """
    def proof_of_inc(self, digest):
        # starting the proof with the root
        proof = self.calc_root()
        # transforming the digest to binary (from hex)
        digest = hex2binary(digest)
        # setting the current node we are working on to be root
        current_node = self.root
        # setting the depth of the tree as the length
        depth = self.length
        # the last father we worked on, currently None
        last_father = None
        # for every digit in the digest, go down
        for digit in digest:
            # if we reached the end and the current node is none,
            # add the default value of this node to the proof
            if current_node is None:
                current_node = last_father
                proof += " " + str(self.defaults[depth])
                break
            # go down the tree
            depth -= 1
            # if we reached the bottom, exit (simply for safety reasons)
            if depth == 0:
                break
            # go right if 1 and left if 0
            if digit == '0':
                last_father = current_node
                current_node = current_node.get_left()
            elif digit == '1':
                last_father = current_node
                current_node = current_node.get_right()
            else:
                return None
        # if we reached the bottom(or none), go up and add each brother to the proof
        while current_node is not None:
            # if we came up from left, add the right brother to the proof
            if digest[len(digest)-1-depth] == '0':
                if current_node.get_right() is None:
                    proof += " " + str(self.defaults[depth])
                else:
                    proof += " " + current_node.get_right().get_data()
            # if we came up from right, add the left brother to the proof
            elif digest[len(digest)-1-depth] == '1':
                if current_node.get_left() is None:
                    proof += " " + str(self.defaults[depth])
                else:
                    proof += " " + current_node.get_left().get_data()
            else:
                return None
            # go up
            current_node = current_node.get_father()
            depth += 1
        # in case our proof is empty so they only proof we need is the root
        return proof

    """
    check_proof:
    checking the proof of the digest given, according to the leaf given
    """
    def check_proof(self, digest, leaf, proof):
        i = 0
        # splitting the proof to the proof and root
        split_proof = proof.split(' ')
        # if we have less than two items (meaning only the root or empty), than this proof is illegal
        if len(split_proof) < 2:
            return None
        # setting root and proof array (after separating them)
        root = split_proof[0]
        proof_arr = split_proof[1:]
        # transforming the digest to binary (from hex)
        digest = hex2binary(digest)
        # if the proof has only one item, which is the correct root
        if len(proof_arr) == 1 and root == proof_arr[0]:
            return True
        # if the leaf is 0, only add 0 if we have a full proof(the len of proof is the len of digest),
        # otherwise, change digest to only include the relevant bits
        if leaf == '0':
            if len(proof_arr) == len(digest):
                proof_arr.insert(0, '0')
            else:
                digest = digest[:len(proof_arr)]
        # if the leaf is 1, insert the leaf (we must have a full proof)
        elif leaf == '1':
            proof_arr.insert(0, '1')
        # otherwise, invalid leaf was given
        else:
            return None
        # go through the proof array, and add each two first items together, until we reach the root
        while len(proof_arr) != 1:
            if digest[len(digest)-i-1] == '0':
                proof_arr.insert(0, hashlib.sha256((proof_arr[0] + proof_arr[1]).encode('utf-8')).hexdigest())
            elif digest[len(digest)-i-1] == '1':
                proof_arr.insert(0, hashlib.sha256((proof_arr[1] + proof_arr[0]).encode('utf-8')).hexdigest())
            else:
                return None
            proof_arr.pop(1)
            proof_arr.pop(1)
            i += 1
        # checking if the root we received is the same as the real root
        if proof_arr[0] == root:
            return True
        else:
            return False


"""
hex2binary:
transforming an hex number to a binary (sending as string of 1's and 0's)
hex_num is a string representing an hex number, for example: "a5f314b2"
"""
def hex2binary(hex_num):
    bin_num = ""
    # for every digit in the hex number, convert ot binary accordingly
    for digit in hex_num:
        order = ord(digit)
        # if a number
        if ord('9') >= order >= ord('0'):
            bin_num += format(int(order - ord('0')), '#006b')[2:]
        # if a lower char
        elif ord('f') >= order >= ord('a'):
            bin_num += format(int(order - ord('a') + 10), '#006b')[2:]
        # if a capital char
        elif ord('F') >= order >= ord('A'):
            bin_num += format(int(order - ord('A') + 10), '#006b')[2:]
        # not a valid hex digit
        else:
            return None
    # returning the binary number we received
    return bin_num

"""
activate:
This is like a "main" function, that activates the whole program,
receives input and prints output
"""
def activate():
    # for the merkle tree exercises
    mrlt = MerkleTree()
    # for the sparse merkle tree exercises
    mrlt2 = SparseMerkleTree()
    # go forever, we did not define a stopping signal
    while True:
        # get input
        input1 = input()
        input_lst = input1.split(" ")
        # get the mission number
        mission = input_lst[0]
        length = len(input1)
        # insert leaf to mrlt
        if mission == '1':
            str1 = input1[2:]
            mrlt.insert_leaf(str1)
        # calculate root of mrlt
        elif mission == '2':
            output = mrlt.calc_root()
            print_output(output)
        # get proof of inc of an index in mrlt
        elif mission == '3':
            if length == 1:
                print("")
                continue
            # get the index
            index = int(input1[2:])
            output = mrlt.proof_of_inc(index)
            print_output(output)
        # check proof of inc for values in mrlt
        elif mission == '4':
            if len(input_lst) < 3:
                print("")
                continue
            # the string we are checking the proof for
            str1 = input_lst[1]
            proof_arr = input_lst[2:]
            proof = " "
            # the proof
            proof = proof.join(proof_arr)
            output = mrlt.check_proof(str1, proof)
            print_output(output)
        # creating secret key and public key
        elif mission == '5':
            output = mrlt.create_sk_pk()
            print_output(output)
        # creating a signature of the root using a secret key
        elif mission == '6':
            if length == 1:
                print("")
                continue
            # the secret key
            sk = input1[2:] + '\n'
            input2 = input()
            while input2 != "":
                sk += input2 + '\n'
                input2 = input()
            output = mrlt.signature(sk)
            print_output(output)
        # verifying signature
        elif mission == '7':
            if length == 1:
                print_output(None)
                continue
            # the public key
            pk = input1[2:] + '\n'
            input2 = input()
            while input2 != "":
                pk += input2 + '\n'
                input2 = input()
            new_input = input().split(" ")
            # the signature to verify
            signature = new_input[0]
            # the text we signed on
            text = new_input[1]
            output = mrlt.verify_signature(pk, signature, text)
            print_output(output)
        # inserting leaf to mrlt2
        elif mission == '8':
            if length == 1:
                print_output(None)
                continue
            digest = input_lst[1]
            mrlt2.insert_leaf(digest)
        # calculating root of mrlt2
        elif mission == '9':
            output = mrlt2.calc_root()
            print_output(output)
        # creating proof of inclusion for a digest in mrlt2
        elif mission == '10':
            digest = input_lst[1]
            output = mrlt2.proof_of_inc(digest)
            print_output(output)
        # checking proof of inclusion in mrlt2
        elif mission == '11':
            # digest
            digest = input_lst[1]
            # leaf of the proof
            leaf = input_lst[2]
            # the proof
            proof_arr = input_lst[3:]
            proof = " "
            proof = proof.join(proof_arr)
            output = mrlt2.check_proof(digest, leaf, proof)
            print_output(output)
        # invalid input, go down a line and continue
        else:
            print("")
            continue

"""
print_output:
getting output and printing it. If it is None, printing nothing (going down a line)
"""
def print_output(output):
    if output is None:
        print("")
    else:
        print(output)

# calling activate
activate()
