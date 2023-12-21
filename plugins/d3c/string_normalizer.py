import pandas as pd
import os

# Default path to corpus files for loading custom synonym words.
DEFAULT_SYNONYM_FILE = os.path.join(os.path.dirname(__file__), "data/synonym_list.xlsx")

# Aliases for each column name
COLUMN_NAME_ALIASES = {
    'Device Role': ['device_role'],
    'Manufacturer': ['manufacturer'],
}
# Lookup table for aliases to column names
COLUMN_NAME_ALIAS_MAP = {}
# initialiser for the alias map.
for column, aliasList in COLUMN_NAME_ALIASES.items():
    COLUMN_NAME_ALIAS_MAP[column] = column
    for alias in aliasList:
        COLUMN_NAME_ALIAS_MAP[alias] = column


class StringNormalizer:
    """
    A class for normalizing an input string by matching it against a dictionary of given synonyms.
    """

    def __init__(self, synonyms_path: str = DEFAULT_SYNONYM_FILE):
        """
        Initializes the class with the provided synonyms file path.
        Reads the synonyms from the Excel file and assigns them to instance variables.

        Parameters:
            synonyms_path (str): Path to the Excel file containing synonyms.
                Defaults to DEFAULT_SYNONYM_FILE.
        """
        self.all_synonym_dict, self.specific_synonym_dict = self._read_synonyms_from_xlsx(synonyms_path)

    def _read_synonyms_from_xlsx(self, synonyms_path):
        """
        Reads synonyms from an Excel file and returns two dictionaries.

        Parameters:
            synonyms_path (str): Path to the Excel file containing synonyms.

        Returns:
            tuple: A tuple containing two dictionaries.
                - all_synonym_dict (dict): Dictionary containing all synonyms.
                - specific_synonym_dict (dict): Dictionary containing synonyms specific to each sheet.

        Raises:
            Exception: If there is an error reading the Excel file.
        """
        all_synonym_dict = {}
        specific_synonym_dict = {}
        try:
            absolute_path = os.path.dirname(__file__)
            repo = os.path.join(absolute_path, "data/synonym_list.xlsx")
            xls = pd.ExcelFile(repo)
            for sheet_name in xls.sheet_names:
                spec_dict = {}
                df = xls.parse(sheet_name)
                for col in df.columns:
                    master_word = col
                    synonyms = df[master_word].dropna().tolist()
                    all_synonym_dict[master_word] = [master_word] + synonyms
                    spec_dict[master_word] = [master_word] + synonyms
                specific_synonym_dict[sheet_name] = spec_dict
            return all_synonym_dict, specific_synonym_dict

        except Exception as e:
            print(f"Error reading Excel file: {e}")
            return {}

    def _get_master_word_from_dictionary(self, test_str: str, dictionary: dict, case_sensitive=False):
        """
        Finds the master word from the given dictionary based on a test string.

        Parameters:
            test_str (str): The test string to search for in the dictionary.
            dictionary (dict): The dictionary to search in.
            case_sensitive (bool): Determines whether the search is case sensitive or not.
                Defaults to False.

        Returns:
            str: The master word from the dictionary that matches the test string.
                Returns an empty string if no match is found.
        """
        for master_word, synonyms in dictionary.items():
            if not case_sensitive:
                if test_str.lower() == master_word.lower() or test_str.lower() in [syn.lower() for syn in synonyms]:
                    return master_word
            else:
                if test_str == master_word or test_str in synonyms:
                    return master_word
        return ""

    def normalize(self, test_str: str, specific_dict: str, case_sensitive=False):
        """
        Normalizes a test string based on the specified dictionary of synonyms.

        Parameters:
            test_str (str): The test string to normalize.
            specific_dict (str): The specific dictionary to use for normalization.
                If not provided or not found, the default dictionary is used.
            case_sensitive (bool): Determines whether the normalization is case sensitive or not.
                Defaults to False.

        Returns:
            str: The normalized string based on the specified dictionary.
                Returns an empty string if the test string is empty or no match is found in the dictionaries.
        """
        if not test_str:
            print("WARNING: No input string to normalize.")
            return ""
        specific_dict = COLUMN_NAME_ALIAS_MAP.get(specific_dict, specific_dict)
        if specific_dict and (specific_dict in self.specific_synonym_dict.keys()):
            return self._get_master_word_from_dictionary(test_str, self.specific_synonym_dict[specific_dict], case_sensitive)
        else:
            return self._get_master_word_from_dictionary(test_str, self.all_synonym_dict, case_sensitive)


if __name__ == "__main__":
    # NOTE: The following code provides examples on how to use the class above as well as testing it's functionality.

    def test(test_str, specific_dict: str = "", case_sensitive=False):
        """
        Tests the normalization of a test string and prints the result.

        Parameters:
            test_str (str): The test string to normalize.
            specific_dict (str): The specific dictionary to use for normalization.
                Defaults to an empty string, which indicates using the default dictionary.
            case_sensitive (bool): Determines whether the normalization is case sensitive or not.
                Defaults to False.
        """
        print(f"'{test_str}' -> '{sn.normalize(test_str, specific_dict, case_sensitive)}'")

    # initialize the StringNormalizer class with default parameters
    sn = StringNormalizer()

    # Test "Manufacturer" synonyms
    test("io device")
    test("Siemens Ag")
    test("Siemens AG")
    test("SIEMENS")
    test("siemens.com")
    test("Phoenix Contact GmbH")
    test("PxC")
    test("Asea Brown Boveri")
    test("ABB Ltd")

    # Test "Manufacturer" synonyms under restriction of the search space
    test("SIEMENS", "Device Role")  # returns an empty string because of lookup in wrong search space
    test("SIEMENS", "Manufacturer")
    test("siemens.com", "Manufacturer")
    test("Phoenix Contact GmbH", "Manufacturer")
    test("PxC", "Manufacturer")
    test("Asea Brown Boveri", "Manufacturer")

    # Test "Device Role" synonyms
    test("PLC")
    test("SPS")
    test("io device")
    test("Firewall")
    test("switch")
    test("bus coupler")
    test("BK")
    test("Human Machine Interface")
    test("Domain-Controller")

    # Test "Device Role" synonyms under restriction of the search space
    test("SPS", "Device Role")
    test("io device", "Device Role")
    test("Firewall", "Device Role")
    test("switch", "Device Role")
    test("bus coupler", "Device Role")
