public class Main {
    public static void main(String[] args) throws Exception {
        PasswordManager manager = new PasswordManager("vault.dat");

        manager.addEntry("gmail", "user123", "MyStrongPassword!");
        manager.addEntry("github", "devUser", "CodeMaster09");

        System.out.println("Stored entries:");
        manager.listEntries();

        System.out.println("\nPassword for github:");
        System.out.println(manager.getPassword("github"));
    }
}
