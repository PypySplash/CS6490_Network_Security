import java.io.*;
import java.util.*;

public class EncryptionSystem {
    // 8個替換表，每個表256個元素
    private int[][] substitutionTables;
    // 反向替換表，用於解密
    private int[][] reverseSubstitutionTables;
    // 64位元金鑰
    private char[] key;
    
    // 建構函式
    public EncryptionSystem(String password) {
        // 將密碼轉換為金鑰
        this.key = password.toCharArray();
        if (this.key.length != 8) {
            throw new IllegalArgumentException("密碼必須是8個字元");
        }
        
        // 初始化替換表
        initializeSubstitutionTables();
    }
    
    // 初始化替換表
    private void initializeSubstitutionTables() {
        substitutionTables = new int[8][256];
        reverseSubstitutionTables = new int[8][256];
        Random random = new Random(Arrays.hashCode(key)); // 使用金鑰作為隨機種子
        
        // 為每個位置創建唯一的替換表
        for (int i = 0; i < 8; i++) {
            // 創建0-255的列表
            List<Integer> numbers = new ArrayList<>();
            for (int j = 0; j < 256; j++) {
                numbers.add(j);
            }
            
            // 隨機打亂順序
            for (int j = 0; j < 256; j++) {
                int randomIndex = random.nextInt(numbers.size());
                substitutionTables[i][j] = numbers.remove(randomIndex);
                // 儲存反向映射用於解密
                reverseSubstitutionTables[i][substitutionTables[i][j]] = j;
            }
        }
    }
    
    // 加密單個字元
    private char encryptChar(char c, int position, int round) {
        // 與金鑰進行XOR
        char xored = (char)(c ^ key[position]);
        // 使用替換表
        int substituted = substitutionTables[position][xored & 0xFF];
        return (char)substituted;
    }
    
    // 解密單個字元
    private char decryptChar(char c, int position, int round) {
        // 使用反向替換表
        int reverseSubstituted = reverseSubstitutionTables[position][c & 0xFF];
        // 與金鑰進行XOR
        return (char)(reverseSubstituted ^ key[position]);
    }
    
    // 向左循環位移
    private char[] leftCircularShift(char[] data) {
        char[] result = new char[8];
        for (int i = 0; i < 8; i++) {
            int value = data[i] & 0xFF;
            value = ((value << 1) | (value >> 7)) & 0xFF;
            result[i] = (char)value;
        }
        return result;
    }
    
    // 向右循環位移
    private char[] rightCircularShift(char[] data) {
        char[] result = new char[8];
        for (int i = 0; i < 8; i++) {
            int value = data[i] & 0xFF;
            value = ((value >> 1) | (value << 7)) & 0xFF;
            result[i] = (char)value;
        }
        return result;
    }
    
    // 加密方法
    public char[] encrypt(char[] input, PrintWriter out) {
        if (input.length != 8) {
            throw new IllegalArgumentException("輸入必須是8個字元");
        }
        
        char[] current = input.clone();
        
        // 16輪加密
        for (int round = 0; round < 16; round++) {
            // 加密每個字元
            for (int i = 0; i < 8; i++) {
                current[i] = encryptChar(current[i], i, round);
            }
            // 執行置換（向左循環位移）
            current = leftCircularShift(current);
            
            // 輸出每一輪的結果
            out.println(String.format("Encryption Round %2d: %s", round + 1, toHexString(current)));
        }
        
        return current;
    }
    
    // 解密方法
    public char[] decrypt(char[] input, PrintWriter out) {
        if (input.length != 8) {
            throw new IllegalArgumentException("輸入必須是8個字元");
        }
        
        char[] current = input.clone();
        
        // 16輪解密
        for (int round = 15; round >= 0; round--) {
            // 先執行反向置換（向右循環位移）
            current = rightCircularShift(current);
            // 解密每個字元
            for (int i = 0; i < 8; i++) {
                current[i] = decryptChar(current[i], i, round);
            }
            
            // 輸出每一輪的結果
            out.println(String.format("Decryption Round %2d: %s", 16 - round, toHexString(current)));
        }
        
        return current;
    }
    
    // 將字元陣列轉換為十六進位字串
    private static String toHexString(char[] data) {
        StringBuilder sb = new StringBuilder();
        for (char c : data) {
            sb.append(String.format("%02X", (int)c));
        }
        return sb.toString();
    }
    
    // 主程式
    public static void main(String[] args) {
        try {
            // 建立輸出檔案
            PrintWriter out = new PrintWriter("encryption_output.txt");
            
            // 創建加密系統實例
            EncryptionSystem system = new EncryptionSystem("Secret12");
            
            // 測試案例1
            char[] input1 = "TestData".toCharArray();
            out.println("Test 1:");
            out.println("Input: " + toHexString(input1));
            
            // 加密
            out.println("Start Encryption:");
            char[] encrypted1 = system.encrypt(input1, out);
            out.println("Encryption Result: " + toHexString(encrypted1));
            
            // 解密
            out.println("\nStart Decryption:");
            char[] decrypted1 = system.decrypt(encrypted1, out);
            out.println("Decryption Result: " + toHexString(decrypted1));
            out.println();
            
            // 測試案例2（改變一個位元）
            char[] input2 = input1.clone();
            input2[0] = (char)(input2[0] ^ 1); // 變更最低位元
            
            out.println("Test 2 (change a bit):");
            out.println("Input: " + toHexString(input2));
            
            // 加密
            out.println("\nStart Decryption:");
            char[] encrypted2 = system.encrypt(input2, out);
            out.println("Encryption Result: " + toHexString(encrypted2));
            
            // 解密
            out.println("\nStart Decryption:");
            char[] decrypted2 = system.decrypt(encrypted2, out);
            out.println("Decryption Result: " + toHexString(decrypted2));
            
            out.close();
            System.out.println("Result write to encryption_output.txt");
            
        } catch (IOException e) {
            System.err.println("write in error: " + e.getMessage());
        }
    }
}