#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <regex>
#include <string>
#include <unordered_map>

using namespace std;

class User {
private:
  string email;
  string passwordHash;
  string secretKey;
  bool isLocked;
  chrono::steady_clock::time_point lastLoginAttempt;

public:
  User() : isLocked(false) {}
  User(string _email, string _password) : email(_email), isLocked(false) {
    passwordHash = hashPassword(_password);
    secretKey = generateSecretKey();
  }

  string getEmail() const { return email; }

  string getPasswordHash() const { return passwordHash; }

  string getSecretKey() const { return secretKey; }

  bool getIsLocked() const { return isLocked; }

  void setIsLocked(bool locked) { isLocked = locked; }

  chrono::steady_clock::time_point getLastLoginAttempt() const {
    return lastLoginAttempt;
  }

  void updateLastLoginAttempt() {
    lastLoginAttempt = chrono::steady_clock::now();
  }

  static string hashPassword(const string &password) {
    return to_string(hash<string>{}(password));
  }

  static string generateSecretKey() {
    static const string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static mt19937 rng(static_cast<unsigned int>(time(nullptr)));
    static uniform_int_distribution<int> distribution(0, characters.size() - 1);

    string key;

    for (int i = 0; i < 6; ++i) {
      key += characters[distribution(rng)];
    }
    return key;
  }
};

class UserAuthentication {
private:
  unordered_map<string, User> userDatabase;
  unordered_map<string, int> loginAttempts;
  const int maxLoginAttempts = 3;
  const int lockoutDurationSeconds = 60;
  ofstream logFile;

public:
  UserAuthentication() {
    logFile.open("login_logs.txt", ofstream::app);
    if (!logFile.is_open()) {
      cerr << "Unable top open the log file." << endl;
    }
  }

  ~UserAuthentication() {
    if (logFile.is_open()) {
      logFile.close();
    }
  }

  void start() {
    cout << "Welcome to User Authentication App!" << endl;
    char choice;
    do {
      cout << "Choose an option:" << endl;
      cout << "1. Signup" << endl;
      cout << "2. Login" << endl;
      cout << "3. Exit" << endl;
      cout << "Enter your choice: ";
      cin >> choice;

      switch (choice) {
      case '1':
        signUpProcess();
        break;
      case '2':
        loginProcess();
        break;
      case '3':
        cout << "Exiting the User Authentication App. Goodbye!" << endl;
        break;
      default:
        cout << "Invalid choice. Please try again." << endl;
      }
    } while (choice != '3');
  }

private:
  void signUpProcess() {
    string email, password;

    cout << "Sign Up" << endl;
    cout << "Enter your email address: ";
    cin >> email;

    if (userDatabase.find(email) != userDatabase.end()) {
      cout << "Error: This email is already registered." << endl;
      return;
    }

    cout << "Enter your password: ";
    cin >> password;

    if (!isValidEmail(email)) {
      cout << "Error: Invalid email address." << endl;
      return;
    }

    if (!isValidPassword(password)) {
      cout << "Error: Invalid password. Password should be at least 8 "
              "characters long."
           << endl;
      return;
    }

    User newUser(email, password);
    userDatabase[email] = newUser;

    cout << "Sign-up successful!" << endl;
    cout << "Your 2FA code: " << newUser.getSecretKey() << endl;
  }

  void loginProcess() {
    string email, password, secretKey;

    cout << "Login" << endl;
    cout << "Enter your email address: ";
    cin >> email;

    if (userDatabase.find(email) == userDatabase.end()) {
      cout << "Error: User not found. Please sign up first." << endl;
      return;
    }

    cin.ignore();

    cout << "Enter your password: ";
    password = getPasswordFromConsole();

    User &user = userDatabase[email];

    if (user.getIsLocked()) {
      auto currentTime = chrono::steady_clock::now();
      auto lockoutDuration = chrono::seconds(lockoutDurationSeconds);
      if (currentTime - user.getLastLoginAttempt() < lockoutDuration) {
        cout << "Error: Account is locked. Please try again later." << endl;
        return;
      } else {
        user.setIsLocked(false);
        loginAttempts[email] = 0;
      }
    }

    if (user.getPasswordHash() != User::hashPassword(password)) {
      cout << "Error: Invalid password. Please try again." << endl;
      loginAttempts[email]++;
      if (loginAttempts[email] >= maxLoginAttempts) {
        user.setIsLocked(true);
        user.updateLastLoginAttempt();
        logEvent(email, "Account locked due to too many failed login attempts");
        cout << "Error: Too many failed login attempts. Account is now locked."
             << endl;
      }
      return;
    }

   while(true){
    cout << "Enter your 2FA code or type 'resend' to request again: ";
        cin >> secretKey;

        if (secretKey == "resend") {
            cout << "Requesting 2FA code again..." << endl;
            secretKey = user.getSecretKey(); // Get the secret key from user object
            cout << "2FA code: " << secretKey << endl; // Simulate sending the 2FA code
            continue; // Go back to the start of the loop to prompt user again
        }

        if (secretKey != user.getSecretKey()) {
            cout << "Error: Invalid 2FA code. Please try again." << endl;
        } else {
            break; // Break out of the loop if the code is valid
        }
   }

    cout << "Login successful!" << endl;
    cout << "Welcome " << user.getEmail() << " to User Authentication App."
         << endl;
    loggedInMenu();
  }

  void loggedInMenu() {
    char choice;
    do {
      cout << "Choose an option:" << endl;
      cout << "1. Logout" << endl;
      cout << "2. Exit" << endl;
      cout << "Enter your choice: ";
      cin >> choice;

      switch (choice) {
      case '1':
        cout << "Logging out..." << endl;
        return;
      case '2':
        cout << "Exiting the User Authentication App. Goodbye!" << endl;
        exit(0);
      default:
        cout << "Invalid choice. Please try again." << endl;
      }
    } while (true);
  }

  string getPasswordFromConsole() {
    string password;
    char ch;
    cout << "Enter your password: ";
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch != '\r') { // Exclude carriage return
            password.push_back(ch);
            cout << '*';
        }
    }
    cout << endl;
    return password;
}

  bool isValidEmail(const string &email) const {
    // Basic email validation using regex
    regex emailPattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    return regex_match(email, emailPattern); // DSA: Regular expressions
  }

  bool isValidPassword(const string &password) const {
    // Perform password validation checks
    // In a real-world scenario, implement more complex password policies
    return password.length() >= 8;
  }

  void logEvent(const string &email, const string &message) {
    if (logFile.is_open()) {
      auto currentTime =
          chrono::system_clock::to_time_t(chrono::system_clock::now());
      logFile << "[" << ctime(&currentTime) << "] ";
      logFile << "User: " << email << " - " << message
              << endl; // DSA: File handling
      logFile.flush();
    }
  }
};

int main() {
  UserAuthentication auth;
  auth.start();
  return 0;
}