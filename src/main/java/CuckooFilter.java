import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;


public class CuckooFilter {

    private static final int MAX_TRIES_WHEN_ADDING = 500;
    public static final String ANSI_YELLOW_BACKGROUND = "\u001B[43m";
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_CYAN_BACKGROUND = "\u001B[46m";
    private MessageDigest sha256 = null;
    private MessageDigest sha1 = null;
    private static int fingerprintSize = 0;
    private byte[] fingerprintMask;
    private static ByteArray filterTable = null;
    private ItemInfo lastVictim = null;
    private static double loadFactor = 0;
    private int numOfOccupiedEntries;
    private int totalEntries = 0;

    public CuckooFilter(int fingerprintSize, int numOfBuckets, int numOfEntries) {
        if(fingerprintSize <= 0 || numOfBuckets <= 0 || numOfEntries <= 0)
            throw new IllegalArgumentException("All of these 3 arguments should be positive and non-zero.");
        if(!isPowerOf2(numOfBuckets))
            throw new IllegalArgumentException("The number of Buckets in this prototype has to be power of 2, received " + numOfBuckets);
        if(fingerprintSize > 16 * 8)
            throw new IllegalArgumentException("Fingerprint size in this prototype cannot be greater than " + 32*8  +" bites, received " + fingerprintSize);

        this.fingerprintSize = fingerprintSize;  // Bits
        int fingerprintByte = fingerprintSizeInBytes(); // Bytes
        this.fingerprintMask = new byte[fingerprintByte];
        if(fingerprintSize % 8 != 0) { // Mask will take care for length that is not a product of 8
            for(int i = 1; i < fingerprintByte; i++) {
                this.fingerprintMask[i] = (byte)(0xffffffff);
            }
            this.fingerprintMask[0] = 0x01;
            for(int i = 0; i < ((fingerprintSize-1) % 8); i++) {
                this.fingerprintMask[0] = (byte)((this.fingerprintMask[0] << 1) | 1);
            }
        }

        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("SHA1 can not be found.");
        }

        try {
            sha256 = MessageDigest.getInstance("SHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("SHA256 can not be found.");
        }

        this.numOfOccupiedEntries = 0;
        this.totalEntries = (numOfBuckets * numOfEntries);
        // To construct an empty table for the filter
        filterTable = new ByteArray(fingerprintSize, numOfBuckets, numOfEntries);
    }


    /**
     * Lookup determines if the input object exist in the filter, however, the existence in the filter does not guarantee the existence in the database
     * @param o
     * @return
     */
    public boolean lookup(Object o) {
        ItemInfo info = itemInfoObj(o);
        System.out.println(ANSI_YELLOW_BACKGROUND+"lookup an item "+o+", "+info.toString()+ " Current Loadfactor="+getLoadFactor()+ ANSI_RESET);

        if(lastVictim != null) {
            if(Arrays.equals(info.fingerprint, lastVictim.fingerprint)) {
                return true;
            }
        }

        if(filterTable.ifBucketContains(info.bucket1Index, info.fingerprint)) {
            return true;
        }
        if(filterTable.ifBucketContains(info.bucket2Index, info.fingerprint)) {
            return true;
        }

        return false;
    }

    /**
     * Add one object to the database will automatically add the object to the filter
     * @param o
     * @return
     */
    public boolean add(Object o) {
        if(o == null)
            throw new IllegalArgumentException("Object can not be null");

        numOfOccupiedEntries++;
        ItemInfo info = itemInfoObj(o);
        boolean result = addItem(info);
        System.out.println(ANSI_YELLOW_BACKGROUND+ "add an item "+o+", "+info.toString() + " Current Loadfactor="+getLoadFactor()+ ANSI_RESET);
        return result;
    }

    /**
     * The add algorithm reference to the paper "Cuckoo Filter: Practically Better Than Bloom"
     * @param info
     * @return
     */
    private boolean addItem(ItemInfo info) {

        // If bucket1 or bucket2 has an empty entry then add the fingerprint in to that bucket
        if(filterTable.hasEmptyEntry(info.bucket1Index)) {
            filterTable.insert(info.fingerprint, info.bucket1Index);
            return true;
        }

        if(filterTable.hasEmptyEntry(info.bucket2Index)) {
            filterTable.insert(info.fingerprint, info.bucket2Index);
            return true;
        }

        // The filter is full, return false to indicate the status
        if(lastVictim != null) {
            numOfOccupiedEntries--;
            return false;
        }

        // Randomly pick buckt1 or buckt2
        Random random = new Random();
        int pickedBucket = random.nextInt(2);
        int destination;
        if(pickedBucket == 1) {
            destination = info.bucket2Index;
        }else {
            destination = info.bucket1Index;
        }
        byte[] fingerprint = info.fingerprint;
        int tries = 0;

        while(++tries <= MAX_TRIES_WHEN_ADDING) {
            byte[] oldFingerprint;
            if(filterTable.hasEmptyEntry(destination)) {
                filterTable.insert(fingerprint, destination);
                return true;
            } else {
                // Randomly get an entry to kick out from the bucket
                oldFingerprint = filterTable.randomGet(destination);
                filterTable.swap(fingerprint, destination, oldFingerprint);
            }
            fingerprint = oldFingerprint;
            destination = xor(fingerprint, destination);
        }
        // The "unlucky bird" got kicked out from its en"tree" is now a victim
        lastVictim = new ItemInfo();
        lastVictim.fingerprint = fingerprint;
        lastVictim.bucket1Index = destination;
        lastVictim.bucket2Index = xor(fingerprint, destination);
        return true;
    }


    /**
     * Deletion algorithm reference to the paper "Cuckoo Filter: Practically Better Than Bloom"
     * @param o
     * @return
     */
    public boolean delete(Object o) {

        if (o == null)
            throw new IllegalArgumentException("Object can not be null.");

        ItemInfo info = itemInfoObj(o);
        numOfOccupiedEntries--;

        // If the item does not exist in both bucket1 or bucket2 return false to indicate the failure of deletion
        if (!filterTable.ifBucketContains(info.bucket1Index, info.fingerprint) && !filterTable.ifBucketContains(info.bucket2Index, info.fingerprint))
            return false;

        boolean deleted = false;
        // Delete the one and only one fingerprint of the item from one of the bucket if multiple fingerprints exist in multiple buckets
        if (filterTable.ifBucketContains(info.bucket1Index, info.fingerprint)) {
            filterTable.delete(info.fingerprint, info.bucket1Index);
            deleted = true;
        } else if (filterTable.ifBucketContains(info.bucket2Index, info.fingerprint)) {
            filterTable.delete(info.fingerprint, info.bucket2Index);
            deleted = true;
        }

        // If the deletion makes a room for the previous "unlucky bird", now we can welcome it back
        if (deleted) {
            if (lastVictim != null) {
                numOfOccupiedEntries++;
                ItemInfo infoVic = new ItemInfo();
                infoVic.fingerprint = Arrays.copyOf(lastVictim.fingerprint, lastVictim.fingerprint.length);
                infoVic.bucket1Index = lastVictim.bucket1Index;
                infoVic.bucket2Index = lastVictim.bucket2Index;
                lastVictim = null;
                System.out.println(ANSI_YELLOW_BACKGROUND + "add the previous victim item " + info.toString() + " Current Loadfactor=" + getLoadFactor() + ANSI_RESET);
                addItem(infoVic);
                return deleted;
            }
        }
        System.out.println(ANSI_YELLOW_BACKGROUND+ "delete an item "+o+", "+info.toString()  + " Current Loadfactor="+getLoadFactor()+ ANSI_RESET);
        return deleted;
    }

    private class ItemInfo {
        int bucket1Index = -1;
        int bucket2Index = -1;
        byte[] fingerprint = null;
        @Override
        public String toString() {
            return "bucket1: " + bucket1Index + ", bucket2: " + bucket2Index + ", fingerprint: " + readableByteArray(fingerprint) + " = " +byteArrayToString(fingerprint);
        }
    }

    private void calculateLoadFactor() {
        this.loadFactor = (double)this.numOfOccupiedEntries / this.totalEntries;
    }

    private double getLoadFactor() {
        calculateLoadFactor();
        return this.loadFactor;
    }

    /**
     * Calculate the indexes for 2 buckets and the fingerprint
     * @param o
     * @return
     */
    private ItemInfo itemInfoObj(Object o) {
        int h = o.hashCode();
        ItemInfo info = new ItemInfo();
        byte[] item = new byte[8];
        for(int i=0; i < item.length; i++) {
            item[i] = (byte)(h & 0xff);
            h >>= 8;
        }
        byte[] hash = sha256.digest(item); // Hash function for input item

        // Index for bucket 1
        long val = 0;
        for(int i=0; i < 4; i++) {
            val |= (hash[i] & 0xff); // Convert signed number to unsigned (ie. -53 -> 203)
            if(i<3)
                val <<= 8;
        }
        val &= 0x00000000ffffffffL;
        info.bucket1Index = (int) (val % (long) filterTable.size());

        // Fingerprint
        info.fingerprint = new byte[fingerprintSizeInBytes()];
        byte[] hashFP = sha1.digest(item); // Hash function for calculation the fingerprint
        for(int i=0; i < info.fingerprint.length; i++)
            info.fingerprint[i] = hashFP[i];
        if(fingerprintSize % 8 != 0)
            info.fingerprint[0] &= this.fingerprintMask[0];
        if(isZero(info.fingerprint)) // Avoiding fingerprints with all zeros (they would be confused with 'no fingerprint' in the table)
            info.fingerprint[0] = 1;

        // Index for bucket 2
        info.bucket2Index = xor(info.fingerprint, info.bucket1Index);

        // Check the calculation
        if(xor(info.fingerprint, info.bucket2Index) != info.bucket1Index)
            throw new InternalError("Generated wrong indexes!");

        return info;
    }


    /**
     * Given the index of one bucket and the fingerprint, calculate the other bucket's index
     * This function of calculating the alternate index refer to:
     * https://github.com/lrodero/java_cuckoo_filter
     * @param fingerprint
     * @param index
     * @return
     */
    private int xor(byte[] fingerprint, int index) {
        byte[] hash = sha256.digest(fingerprint);
        byte[] h1 = ByteBuffer.allocate(4).putInt(index).array();
        long val = 0;
        for(int i=0; i < 4; i++) {
            val = hash[i] ^ h1[i];
            val |= (val & 0xff); //Convert signed number to unsigned (ie. -53 -> 203)
            if(i<3)
                val <<= 8;
        }
        val &= 0x00000000ffffffffL;
        return (int) (val % (long) filterTable.size());
    }


    private static int fingerprintSizeInBytes() {
        return (int)Math.ceil(fingerprintSize/8.0D);
    }


    private static void getByteArrayInfo(CuckooFilter filter) {
        filterTable.toString();
    }

    private boolean isZero(byte[] array) {
        if(array == null)
            throw new IllegalArgumentException("Cannot check if a null array is full of zeros");
        for(byte b: array) {
            if(b != 0)
                return false;
        }
        return true;
    }

    private String byteArrayToString(byte[] array) {
        if(array == null)
            return "[NULL]";
        String result = "[";
        for(int i = 0; i < array.length; i++) {
            result += array[i];
            if(i < array.length-1)
                result += ("|");
        }
        result += "]";
        return result;
    }

    private String readableByteArray(byte[] array) {
        if(array == null)
            return "[NULL]";
        String result = "[";
        for(int i = 0; i < array.length; i++) {
            result += readableByte(array[i]);
            if(i < array.length-1)
                result += ("|");
        }
        result += "]";
        return result;
    }

    private boolean isPowerOf2(int number) {
        if(number == 0) return false;
        if((number & (number - 1)) == 0) {
            return true;
        }
        return false;
    }


    private String readableByte(byte b) {
        String a = Integer.toBinaryString(256 + (int) b);
        return (a.substring(a.length() - 8));
    }
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner myObj = new Scanner(System.in);  // Create a Scanner object\
        System.out.println("Hi, welcome for testing my cuckoo filter! If you would like to see an example of the usage please enter 1, and if you want to try with your own configurations please enter 2: ");
        String userPrompt = myObj.nextLine();  // Read user input

        while((userPrompt.equals("1") || userPrompt.equals("2"))) {
            if(userPrompt.equals("1")) {
                Example();
            }
            if(userPrompt.equals("2")) {
                userConfig(myObj);
            }
            System.out.println("Please enter 1 for an example, 2 for testing with your own config and other inputs for exit.");
            userPrompt = myObj.nextLine();
        }
        System.exit(0);
    }



    private static void Example() {
        System.out.println(ANSI_CYAN_BACKGROUND+"TEST CASE 1: CONSTRUCTION OF THE CUCKOO FILTER"+ ANSI_RESET);
        CuckooFilter filter = new CuckooFilter(11,16,2);
        filter.add(9);
        getByteArrayInfo(filter);
        filter.add(9);
        getByteArrayInfo(filter);
        filter.add(11);
        getByteArrayInfo(filter);
        filter.add(18);
        getByteArrayInfo(filter);
        filter.add(19);
        getByteArrayInfo(filter);
        filter.add(233);
        getByteArrayInfo(filter);
        filter.add(55);
        getByteArrayInfo(filter);
        filter.add(233);
        getByteArrayInfo(filter);
        filter.add(18);
        getByteArrayInfo(filter);
        filter.add(303);
        getByteArrayInfo(filter);
        filter.add(303);
        getByteArrayInfo(filter);
        filter.add(303);
        getByteArrayInfo(filter);

        System.out.println(ANSI_CYAN_BACKGROUND+"TEST CASE 2: DEMONSTRATION OF THE POSITIVE QUERY"+ ANSI_RESET);
        System.out.println("The current set contains: 9, 11, 18, 19, 233, 55, 303");
        System.out.println(filter.lookup(9));
        System.out.println(filter.lookup(11));
        System.out.println(filter.lookup(18));
        System.out.println(filter.lookup(19));
        System.out.println(filter.lookup(233));
        System.out.println(filter.lookup(55));
        System.out.println(filter.lookup(303));

        System.out.println(ANSI_CYAN_BACKGROUND+"TEST CASE 3: DEMONSTRATION OF THE NEGATIVE QUERY"+ ANSI_RESET);
        System.out.println("The current set contains: 9, 11, 18, 19, 233, 55, 303");
        System.out.println(filter.lookup(90));
        System.out.println(filter.lookup(101));
        System.out.println(filter.lookup(8));
        filter.delete(9);
        System.out.println("This result for lookup 9 should be TRUE since there were 2 9s in the filer");
        System.out.println(filter.lookup(9));
        filter.delete(9);
        System.out.println("This result for lookup 9 should be False since there were 1 9 in the filter");
        System.out.println(filter.lookup(9));
        filter.delete(11);
        System.out.println("This result for lookup 11 should be False since there were 1 11 in the filter");
        System.out.println(filter.lookup(11));
    }
    private static void userConfig(Scanner myObj) {
        System.out.println("Please enter number of bucket, number of entry and fingerprint size you want in the format (m,b,f): ");
        String userPrompt = myObj.nextLine();
        String[] config = userPrompt.split(",");
        CuckooFilter filter = new CuckooFilter(Integer.valueOf(config[2]),Integer.valueOf(config[0]),Integer.valueOf(config[1]));
        System.out.println("Please enter the operation you want (ex. add 1), and if you want to end the test please enter \"exit\": ");
        userPrompt = myObj.nextLine();
        while(!userPrompt.equals("exit")) {
            if(userPrompt.contains("add")) {
                boolean add = filter.add(userPrompt.split(" ")[1]);
                if(!add) {
                    throw new IllegalArgumentException("Filter is full, can't not add new items");
                }
                getByteArrayInfo(filter);
            } else if(userPrompt.contains("delete")) {
                filter.delete(userPrompt.split(" ")[1]);
                getByteArrayInfo(filter);
            }else if(userPrompt.contains("lookup")) {
                System.out.println(filter.lookup(userPrompt.split(" ")[1]));
            } else {
                System.out.println("Invalid input, please consult the report pdf, if you want to exit, please enter \"exit\".");
            }
            userPrompt = myObj.nextLine();
        }
    }



    public class ByteArray {
        private int bitsPerEntry; //fingerprint Size
        private int numOfBuckets;

        private int numOfEntries;

        private int bytesPerEntry;

        protected byte[] table = null;

        public int size() {
            return numOfBuckets;
        }

        public ByteArray(int bitsPerEntry, int numOfBuckets, int numOfEntries) {

            if(numOfBuckets <= 0)
                throw new IllegalArgumentException("Number of buckets must be a positive number");
            if(numOfEntries <= 0)
                throw new IllegalArgumentException("Number of entries must be a positive number");
            if(bitsPerEntry <= 0)
                throw new IllegalArgumentException("Number of bits per bucket must be a positive number");

            this.bitsPerEntry = bitsPerEntry;
            this.numOfBuckets = numOfBuckets;
            this.numOfEntries = numOfEntries;
            this.bytesPerEntry = bytesPerEntry();

            // Due to time limitation, this implementation uses a lazy bit presentation way which causes storage waste
            // This implementation does not affect the throughput test of the Algo, and it will be replaced to avoid the storage waste when time permits
            int tableSize = this.bytesPerEntry *  this.numOfEntries * this.numOfBuckets;
            table = new byte[tableSize];
        }

        /**
         * Locate the entry of the oldItem and change it to the newItem. The lookup process of the oldItem in given buket costs O(bucket size)
         * @param newItem
         * @param itemPos
         * @param oldItem
         */
        public void swap(byte[] newItem, int itemPos, byte[] oldItem) {
            if(oldItem == null)
                throw new IllegalArgumentException("The old item can not be null");

            // Locating the first byte of the input bucket
            int firstByteIndex = itemPos * this.bytesPerEntry * this.numOfEntries;

            byte[] entry = new byte[this.bytesPerEntry];
            // Find the entry that contains the oldItem
            for(int i = 0; i < this.numOfEntries; i ++) {
                for(int j = 0; j < this.bytesPerEntry; j++) {
                    entry[j] = table[firstByteIndex + i*this.bytesPerEntry + j];
                }
                if(Arrays.equals(entry, oldItem)) {
                    // Swap the fingerprint of the old item in this entry with the fingerprint of the new item
                    for(int k = 0; k < this.bytesPerEntry; k++) {
                        table[firstByteIndex + i * this.bytesPerEntry+k] = newItem[k];
                    }
                    return;
                }
            }
        }

        /**
         * Add the item to the given bucket
         * @param item
         * @param itemPos
         */
        public void insert(byte[] item, int itemPos) {

            if(item.length != this.bytesPerEntry)
                throw new IllegalArgumentException("The length in byte of input item is different from the length in byte of the entry");
            if(itemPos >= numOfBuckets)
                throw new IllegalArgumentException("Input bucket index exceed the number of bucket");
            if(itemPos < 0)
                throw new IllegalArgumentException("Input bucket index is a negative number");

            // Locating the first byte of the input bucket
            int firstByteIndex = itemPos * this.bytesPerEntry * this.numOfEntries;

            byte[] entry = new byte[this.bytesPerEntry];
            // find the first empty entry in the bucket
            for(int i = 0; i < this.numOfEntries; i ++) {
                for(int j = 0; j < this.bytesPerEntry; j++) {
                    entry[j] = table[firstByteIndex + i*this.bytesPerEntry + j];
                }
                if(isZero(entry)) {
                    // Insert to this entry
                    for(int k = 0; k < this.bytesPerEntry; k++) {
                        table[firstByteIndex + i * this.bytesPerEntry+k] = item[k];
                    }
                    return;
                }
            }
        }

        /**
         * Return a random entry of the bucket
         * @param itemPos
         * @return
         */
        public byte[] randomGet(int itemPos) {

            if(itemPos >= this.numOfBuckets)
                throw new IllegalArgumentException("Input bucket index exceed the number of bucket");
            if(itemPos < 0)
                throw new IllegalArgumentException("Input bucket index is a negative number");

            byte[] item = new byte[this.bytesPerEntry];
            Random random = new Random();
            // Generates random integers 0 to numOfEntries
            int pickedEntry = random.nextInt(numOfEntries);
            int startByteIndex = itemPos*numOfEntries*bytesPerEntry + pickedEntry*bytesPerEntry;
            for(int i = 0; i < this.bytesPerEntry; i++) {
                item[i] = table[startByteIndex+i];
            }
            return item;
        }

        /**
         * Return true if there is an empty entry in the given bucket, otherwise return false
         * @param itemPos
         * @return
         */
        public boolean hasEmptyEntry(int itemPos) {

            if(itemPos >= numOfBuckets)
                throw new IllegalArgumentException("Input bucket index exceed the number of bucket");
            if(itemPos < 0)
                throw new IllegalArgumentException("Input bucket index is a negative number");

            // Locating the first byte of the input bucket
            int firstByteIndex = itemPos * this.bytesPerEntry * this.numOfEntries;

            // Find the first empty entry in the bucket
            for(int i = 0; i < this.numOfEntries; i ++) {
                boolean isEmpty = true;
                for(int j = 0; j < this.bytesPerEntry; j++) {
                    if(table[firstByteIndex + i*this.bytesPerEntry + j] != 0) {
                        isEmpty = false;
                    }
                }
                if(isEmpty) return true;
            }
            return false;
        }


        /**
         * Remove an item from the given bucket
         * @param item
         * @param itemPos
         */
        public void delete(byte[] item, int itemPos) {

            if(item.length != this.bytesPerEntry)
                throw new IllegalArgumentException("The length in byte of input item is different from the length in byte of the entry");
            if(itemPos >= numOfBuckets)
                throw new IllegalArgumentException("Input bucket index exceed the number of bucket");
            if(itemPos < 0)
                throw new IllegalArgumentException("Input bucket index is a negative number");


            // Locating the first byte of the input bucket
            int firstByteIndex = itemPos * this.bytesPerEntry * this.numOfEntries;

            byte[] entry = new byte[this.bytesPerEntry];
            // Find the entry that contains the item
            for(int i = 0; i < this.numOfEntries; i ++) {
                for(int j = 0; j < this.bytesPerEntry; j++) {
                    entry[j] = table[firstByteIndex + i*this.bytesPerEntry + j];
                }
                if(Arrays.equals(entry, item)) {
                    // Empty this entry
                    for(int k = 0; k < this.bytesPerEntry; k++) {
                        table[firstByteIndex + i * this.bytesPerEntry+k] = 0;
                    }
                    return;
                }
            }
        }

        /**
         * Return true if the given bucket contains the given item, otherwise return false
         * @param itemPos
         * @param target
         * @return
         */
        public boolean ifBucketContains(int itemPos, byte[] target) {
            if(itemPos >= numOfBuckets)
                throw new IllegalArgumentException("Input bucket index exceed the number of bucket");
            if(itemPos < 0)
                throw new IllegalArgumentException("Input bucket index is a negative number");


            // Locating affected bytes in table
            int startByteIndex = itemPos * numOfEntries * bytesPerEntry;

            byte[] item = new byte[bytesPerEntry];

            for(int i = 0; i < numOfEntries; i++) {
                for(int j = 0; j < bytesPerEntry; j++) {
                    item[j] = table[startByteIndex + j + i * this.bytesPerEntry];
                }
                // Check if the item equals the one in the current entry
                if(Arrays.equals(item, target)) {
                    return true;
                }
            }
            return false;
        }

        private boolean isZero(byte[] array) {
            if(array == null)
                throw new IllegalArgumentException("Input array for check is null");
            for(byte b: array)
                if(b != 0)
                    return false;
            return true;
        }



        private int bytesPerEntry() {
            return (int) Math.ceil(this.bitsPerEntry / 8.0D);
        }


        @Override
        public String toString() {
            System.out.println("------------------TABLE----------------------");
            int entryCnt = 0;
            int bucketCnt = 0;

            int entryIndex = 0;
            for(int i = 0; i < this.numOfBuckets; i++) {
                System.out.print("Bucket" + (i) + ": ");
                int j;
                for(j = 0 ;j < bytesPerEntry * this.numOfEntries; j++) {
                    System.out.print(table[entryIndex]+" ");
                    entryIndex++;
                }
                System.out.println();
                bucketCnt ++;

            }
            System.out.println("-------------------------------------------");
            return "ByteArray{" +
                    "bitsPerEntry=" + bitsPerEntry +
                    ", numOfBuckets=" + numOfBuckets +
                    ", numOfEntries=" + numOfEntries +
                    ", bytesPerEntry=" + bytesPerEntry +
                    '}';
        }
    }
}



