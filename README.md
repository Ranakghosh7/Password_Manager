/**
 * PasswordManager.java
 *
 * Single-file Java password manager (educational demo).
 *
 * Features:
 * - One-file runnable Java program (Java 11+)
 * - PBKDF2WithHmacSHA256 key derivation
 * - AES/GCM authenticated encryption (12-byte nonce, 128-bit tag)
 * - Vault file contains a small JSON metadata wrapper and base64 ciphertext
 * - Simple CLI: create-vault, add, list, get, remove, export, import, change-master
 *
 * Limitations & warnings:
 * - Minimal serialization format (line-based, escaped). Not for production use.
 * - No Argon2. PBKDF2 iterations are configurable but CPU-bound.
 * - Sensitive data is held in memory when necessary; effort is made to clear char[] where feasible.
 * - No external dependencies used (no JSON library); JSON wrapper is built/parsing by hand.
 * - Use only for learning/prototyping. Audit crypto and consider established password managers for real secrets.
 *
 * Build:
 *   javac PasswordManager.java
 * Run:
 *   java PasswordManager create-vault --file ./vault.dat
 *   java PasswordManager add --file ./vault.dat
 *   java PasswordManager list --file ./vault.dat
 *
 * Author: example
 * Date: 2025
 */

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.Base64;
import java.util.stream.Collectors;

public class PasswordManager {

    // Default settings
    private static final int DEFAULT_PBKDF2_ITERATIONS = 200_000;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    // Vault internal format notes:
    // decrypted payload is lines; each line is an entry with fields separated by '|'
    // fields are escaped (pipe and backslash)
    // fields: id|name|username|password|url|notes|tags(comma)|created|updated
    // This keeps the example short and dependency-free.

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }

        String cmd = args[0];
        Map<String, String> opts = parseArgs(Arrays.copyOfRange(args, 1, args.length));
        String filePath = opts.getOrDefault("--file", System.getProperty("user.home") + File.separator + "vault.dat");

        switch (cmd) {
            case "create-vault":
                createVault(filePath, DEFAULT_PBKDF2_ITERATIONS);
                break;
            case "add":
                addEntry(filePath);
                break;
            case "list":
                listEntries(filePath);
                break;
            case "get":
                getEntry(filePath, opts.get("--name"));
                break;
            case "remove":
                removeEntry(filePath, opts.get("--name"));
                break;
            case "export":
                exportVault(filePath, opts.getOrDefault("--out", "vault-export.dat"));
                break;
            case "import":
                importVault(filePath, opts.getOrDefault("--in", "vault-export.dat"));
                break;
            case "change-master":
                changeMaster(filePath);
                break;
            case "--help":
            case "help":
            default:
                usage();
                break;
        }
    }

    private static void usage() {
        System.out.println("Usage: java PasswordManager <command> [--file path] [options]\n");
        System.out.println("Commands:");
        System.out.println("  create-vault        Create a new encrypted vault file (prompts for master password)");
        System.out.println("  add                 Add an entry (prompts interactively)");
        System.out.println("  list                List entries (shows names and ids)");
        System.out.println("  get --name NAME     Show entry details by name");
        System.out.println("  remove --name NAME  Remove entry by name");
        System.out.println("  export --out PATH   Copy vault file to PATH (encrypted)");
        System.out.println("  import --in PATH    Import an encrypted vault file (replaces current)");
        System.out.println("  change-master       Change master password (re-encrypts vault)");
        System.out.println("Options:");
        System.out.println("  --file PATH         Vault file path (default: ~/.vault.dat)");
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    map.put(a, args[i + 1]);
                    i++;
                } else {
                    map.put(a, "true");
                }
            }
        }
        return map;
    }

    // ------------------ Vault operations ------------------

    private static void createVault(String path, int iterations) throws Exception {
        Path p = Paths.get(path);
        if (Files.exists(p)) {
            System.out.println("Vault already exists at " + path + ". Aborting.");
            return;
        }
        Console console = System.console();
        if (console == null) {
            System.err.println("No console available. Use from terminal.");
            return;
        }
        char[] master = console.readPassword("Choose a master password: ");
        char[] master2 = console.readPassword("Confirm master password: ");
        if (!Arrays.equals(master, master2)) {
            System.out.println("Passwords do not match. Aborting.");
            zero(master);
            zero(master2);
            return;
        }
        // Create empty payload: no entries -> empty string
        byte[] salt = secureRandomBytes(16);
        byte[] key = deriveKey(master, salt, iterations);
        zero(master);
        zero(master2);

        byte[] nonce = secureRandomBytes(GCM_NONCE_BYTES);
        byte[] ciphertext = encryptAESGCM(key, nonce, "".getBytes(StandardCharsets.UTF_8));
        zero(key);

        String wrapper = buildWrapperJson(salt, iterations, nonce, ciphertext);
        Files.createDirectories(p.getParent() == null ? Paths.get(".") : p.getParent());
        Files.write(p, wrapper.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW);
        System.out.println("Vault created at " + path);
    }

    private static void addEntry(String path) throws Exception {
        Vault vault = openVaultInteractive(path, "Enter master password: ");
        if (vault == null) return;

        Console console = System.console();
        if (console == null) {
            System.err.println("No console available. Use from terminal.");
            return;
        }
        String name = readLine(console, "Name: ");
        String username = readLine(console, "Username: ");
        char[] pwdChars = console.readPassword("Password (will not echo): ");
        String password = new String(pwdChars);
        zero(pwdChars);
        String url = readLine(console, "URL (optional): ");
        String notes = readLine(console, "Notes (optional): ");
        String tags = readLine(console, "Tags (comma-separated, optional): ");

        VaultEntry entry = new VaultEntry(UUID.randomUUID().toString(), name, username, password, url, notes, tags, Instant.now().toString(), Instant.now().toString());
        vault.entries.add(entry);

        if (saveVault(vault, path)) {
            System.out.println("Entry added: " + name);
        } else {
            System.out.println("Failed to save vault.");
        }
    }

    private static void listEntries(String path) throws Exception {
        Vault vault = openVaultInteractive(path, "Enter master password: ");
        if (vault == null) return;
        if (vault.entries.isEmpty()) {
            System.out.println("(no entries)");
            return;
        }
        System.out.println("Entries:");
        for (VaultEntry e : vault.entries) {
            System.out.printf(" - %s  (id: %s)\n", e.name, e.id);
        }
    }

    private static void getEntry(String path, String name) throws Exception {
        if (name == null) {
            System.out.println("Provide --name NAME");
            return;
        }
        Vault vault = openVaultInteractive(path, "Enter master password: ");
        if (vault == null) return;
        List<VaultEntry> found = vault.entries.stream().filter(e -> e.name.equalsIgnoreCase(name)).collect(Collectors.toList());
        if (found.isEmpty()) {
            System.out.println("No entry named: " + name);
            return;
        }
        for (VaultEntry e : found) {
            System.out.println("Name: " + e.name);
            System.out.println("Username: " + e.username);
            System.out.println("Password: " + e.password);
            System.out.println("URL: " + e.url);
            System.out.println("Notes: " + e.notes);
            System.out.println("Tags: " + e.tags);
            System.out.println("Created: " + e.createdAt);
            System.out.println("Updated: " + e.updatedAt);
            System.out.println("----");
        }
    }

    private static void removeEntry(String path, String name) throws Exception {
        if (name == null) {
            System.out.println("Provide --name NAME");
            return;
        }
        Vault vault = openVaultInteractive(path, "Enter master password: ");
        if (vault == null) return;
        List<VaultEntry> found = vault.entries.stream().filter(e -> e.name.equalsIgnoreCase(name)).collect(Collectors.toList());
        if (found.isEmpty()) {
            System.out.println("No entry named: " + name);
            return;
        }
        vault.entries.removeAll(found);
        if (saveVault(vault, path)) {
            System.out.println("Removed entries named: " + name);
        } else {
            System.out.println("Failed to save vault.");
        }
    }

    private static void exportVault(String path, String outPath) throws Exception {
        Path p = Paths.get(path);
        if (!Files.exists(p)) {
            System.out.println("Vault does not exist at " + path);
            return;
        }
        Files.copy(p, Paths.get(outPath), StandardCopyOption.REPLACE_EXISTING);
        System.out.println("Vault exported to " + outPath);
    }

    private static void importVault(String path, String inPath) throws Exception {
        Path p = Paths.get(path);
        Files.createDirectories(p.getParent() == null ? Paths.get(".") : p.getParent());
        Files.copy(Paths.get(inPath), p, StandardCopyOption.REPLACE_EXISTING);
        System.out.println("Vault imported from " + inPath + " to " + path);
    }

    private static void changeMaster(String path) throws Exception {
        Vault vault = openVaultInteractive(path, "Enter current master password: ");
        if (vault == null) return;
        Console console = System.console();
        if (console == null) {
            System.err.println("No console available. Use from terminal.");
            return;
        }
        char[] newPass = console.readPassword("New master password: ");
        char[] newPass2 = console.readPassword("Confirm new master password: ");
        if (!Arrays.equals(newPass, newPass2)) {
            System.out.println("Passwords do not match. Aborting.");
            zero(newPass);
            zero(newPass2);
            return;
        }
        // Re-encrypt with new salt & kdf iterations (keep default)
        byte[] salt = secureRandomBytes(16);
        byte[] key = deriveKey(newPass, salt, DEFAULT_PBKDF2_ITERATIONS);
        zero(newPass);
        zero(newPass2);

        byte[] nonce = secureRandomBytes(GCM_NONCE_BYTES);
        byte[] payload = vault.serializePlaintext();
        byte[] ciphertext = encryptAESGCM(key, nonce, payload);
        zero(key);
        Arrays.fill(payload, (byte) 0);

        String wrapper = buildWrapperJson(salt, DEFAULT_PBKDF2_ITERATIONS, nonce, ciphertext);
        Files.write(Paths.get(path), wrapper.getBytes(StandardCharsets.UTF_8), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
        System.out.println("Master password changed and vault re-encrypted.");
    }

    // ------------------ Vault read/write helpers ------------------

    private static Vault openVaultInteractive(String path, String prompt) throws Exception {
        Path p = Paths.get(path);
        if (!Files.exists(p)) {
            System.out.println("Vault does not exist at " + path + ". Run cre
