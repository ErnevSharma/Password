import java.util.List;

/**
 * Check rules on UMD passwords, as described at
 * https://identity.umd.edu/password/changepassword
 * 
 * <ul>
 * <li>A password must be at least 8 and no more than 32 characters in length.
 * <li>A password must contain at least one character from each of the following
 * sets:
 * <ul>
 * <li>Uppercase alphabet (A-Z)
 * <li>Lowercase alphabet (a-z)
 * <li>Number (0-9) and special characters (such as # @ $ & among others)
 * </ul>
 * <li>A password may not begin or end with the space character.
 * <li>A password may not contain more than two consecutive identical
 * characters.
 * <li>A password may not be (or be a variation of ) a dictionary word in
 * English or many other languages. This includes making simple substitutions of
 * digits or punctuation that resemble alphabetic characters (such as replacing
 * the letter S in a common word with the $...
 * <li>Passwords should not contain: carriage return, linefeed, /, \, or a
 * trailing * symbol).
 * </ul>
 *
 */
public class CheckPasswords {

	/**
	 * Count the number of uppercase letters in password; can assume only ASCII
	 * characters
	 */
	static int countUppercaseLetters(String password) {
		int count = 0;

		for (int x = 0; x < password.length(); x++) {
			if (password.charAt(x) >= 'A' && password.charAt(x) <= 'Z')
				count++;
		}

		return count;

	}

	/**
	 * Count the number of lowercase letters in password; can assume only ASCII
	 * characters
	 */
	static int countLowercaseLetters(String password) {
		int count = 0;

		for (int x = 0; x < password.length(); x++) {
			if (password.charAt(x) >= 'a' && password.charAt(x) <= 'z')
				count++;
		}

		return count;

	}

	/**
	 * Count the longest sequences of consecutive identical characters; can assume
	 * only ASCII characters
	 */

	static int longestConsecutiveIdenticalCharacters(String password) {
		int longestConsec = 0;
		int currentLongestConsec = 0;

		int x = 0;
		int y = 0;
		while (x < password.length()) {

			while (y < password.length() && password.charAt(x) == password.charAt(y)) {
				currentLongestConsec++;
				y++;
			}

			x = y;

			if (currentLongestConsec > longestConsec)
				longestConsec = currentLongestConsec;

			currentLongestConsec = 0;

		}

		return longestConsec;
	}

	/**
	 * Check to see if a password is to similar to a dictionary word. It is too
	 * similar if the dictionary word is contained in the password when ignoring
	 * case and treating '1' and 'l' as identical , 'o' and '0' as identical, and
	 * 's' and '$' as identical, and the length of the password is at least 5
	 * characters longer than the word.
	 */
	static boolean similarToWord(String word, String password) {

		int x = 0;
		int y = 0;
		boolean hasMoreThanFive = password.length() > word.length() + 4;
		boolean containsWord = false;

		while (x < password.length()) {

			if (y < word.length() && (password.charAt(x) == word.charAt(y) || password.charAt(x) + 32 == word.charAt(y)
					|| password.charAt(x) == '$' && word.charAt(y) == 's'
					|| password.charAt(x) == '0' && word.charAt(y) == 'o'
					|| password.charAt(x) == '1' && word.charAt(y) == 'l')) {
				y++;
			} else if (y == word.length()) {
				containsWord = true;
				break;
			} else {
				y = 0;

				if (y < word.length()
						&& (password.charAt(x) == word.charAt(y) || password.charAt(x) + 32 == word.charAt(y)
								|| password.charAt(x) == '$' && (word.charAt(y) == 's' || word.charAt(y) == 'S')
								|| password.charAt(x) == '0' && word.charAt(y) == 'o' || word.charAt(y) == 'O')
								|| password.charAt(x) == '1' && word.charAt(y) == 'l')
					y++;

			}

			x++;

		}

		return containsWord && !hasMoreThanFive;

	}

	/** Check to see if password is an acceptable password by UMD standards */
	static boolean checkPassword(String password, List<String> dictionary) {
		boolean hasLowerCase = false;
		boolean hasUpperCase = false;
		boolean hasNonLetter = false;
		boolean inRange = password.length() >= 8 && password.length() <= 32;
		boolean startsOrEndsWithSpace = password.startsWith(" ") || password.endsWith(" ");
		boolean doesNotHaveWord = true;
		boolean noConsec = longestConsecutiveIdenticalCharacters(password) < 3;
		boolean noControlFeed = password.indexOf((char)13) == -1;
		boolean noLineFeed = password.indexOf((char)10) == -1;
		boolean noBackslash = password.indexOf("/") == -1 && password.indexOf("\\") == -1;
		boolean noTrailingAsterisk = !password.endsWith("*");

		for (int x = 0; x < password.length(); x++) {
			if (password.charAt(x) >= 'A' && password.charAt(x) <= 'Z')
				hasUpperCase = true;

			if (password.charAt(x) >= 'a' && password.charAt(x) <= 'z')
				hasLowerCase = true;

			if (password.charAt(x) < 'A' || (password.charAt(x) > 'Z' && password.charAt(x) < 'a')
					|| (password.charAt(x) > 'z'))
				hasNonLetter = true;
		}

		for (String s : dictionary) {
			if (similarToWord(s, password))
				doesNotHaveWord = false;
		}

		return noConsec && 
				doesNotHaveWord && 
				hasLowerCase && 
				hasUpperCase &&
				hasNonLetter && 
				inRange && 
				!startsOrEndsWithSpace &&
				noControlFeed &&
				noLineFeed &&
				noBackslash &&
				noTrailingAsterisk;

	}

}
