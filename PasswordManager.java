import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.HashMap;
import java.util.Base64;

public class PasswordManager {

    private final String filename;
    private final HashMap<String, String[]> vault = new HashMap<>();
    private final String secret = "1234567890123456"; // 16-byte AES key

    public PasswordManager(String filename) throws Exception {
        this.filename = filename;
        load();
    }

    public void addEntry(String site, String user, String pass) throws Exception {
        vault.put(site, new String[]{user, encrypt(pass)});
        save();
    }

    public void listEntries() {
        vault.forEach((site, info) ->
                System.out.println(site + " → " + info[0]));
    }

    public String getPassword(String site) throws Exception {
        if (!vault.containsKey(site)) return "Not found!";
        return decrypt(vault.get(site)[1]);
    }

    private String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(secret.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(secret.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decoded = Base64.getDecoder().decode(data);
        return new String(cipher.doFinal(decoded));
    }

    private void save() throws IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filename))) {
            out.writeObject(vault);
        }
    }

    private void load() {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename))) {
            HashMap<String, String[]> loaded = (HashMap<String, String[]>) in.readObject();
            vault.putAll(loaded);
        } catch (Exception ignored) {}
    }
}
