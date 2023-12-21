import pprint
import pandas as pd
from spellchecker import SpellChecker
import os
# NOTE: The following definitions are used by default and can be customized if changes are made to the regex collection or corpus.

# Default path to corpus files for loading custom words.
DEFAULT_CORPUS_FILE = os.path.join(os.path.dirname(__file__), "data/device_list.xlsx")
# Default list of columns to use from the corpus file. Add or remove column entries from the list to limit or extend the string checking. Column spelling need to match the corpus file.
DEFAULT_CORPUS_COLUMNS = ["Manufacturer", "Device Family", "Device Type", "Article Number"]
# Default list of columns from the corpus, splitted at special chars to enrich the dictionary of custom words.
DEFAULT_COLUMNS_SPELL_SPLIT = ["Manufacturer", "Device Family", "Device Type"]
# Default list of columns from the corpus, splitted at whitespaces to enrich the dictionary of custom words
DEFAULT_COLUMNS_WHITESPACE_SPLIT = ["Device Family", "Device Type"]
# Default flag to enable column specific spell checking, e.g. Manufacturer specific.
DEFAULT_SPECIFIC_CHECKING_ENABLED = False
# Default column used for specific checking, e.g. Manufacturer specific dictionaries are used.
DEFAULT_SPECIFIC_CHECKING_COLUMN = None


class StringChecker:
    """
    A class for checking and suggesting corrections for strings.
    """

    def __init__(
        self,
        additional_language: str = "",
        corpus_file: str = DEFAULT_CORPUS_FILE,
        corpus_cols_to_use: list = DEFAULT_CORPUS_COLUMNS,
        corpus_cols_spell_split: list = DEFAULT_COLUMNS_SPELL_SPLIT,
        corpus_cols_whitespace_split: list = DEFAULT_COLUMNS_WHITESPACE_SPLIT,
        specific_checkers: bool = DEFAULT_SPECIFIC_CHECKING_ENABLED,
        specific_checkers_id: str = DEFAULT_SPECIFIC_CHECKING_COLUMN,
    ):
        """
        Initializes the StringChecker class.

        Parameters:
        - additional_language: str, additional language to be used for spell checking (default: "")
        - corpus_file: str, path to corpus files for loading custom words (default: DEFAULT_CORPUS_FILE)
        - corpus_cols_to_use: list, A list of columns to use from the corpus file. Add or remove column entries from the list to limit or extend the string checking. (default: DEFAULT_COLUMNS)
        - corpus_cols_spell_split: list, A list of columns from the corpus, splitted at special chars to enrich the dictionary of custom words. (default: DEFAULT_COLUMNS_SPELL_SPLIT)
        - corpus_cols_whitespace_split: list, A list of columns from the corpus, splitted at whitespaces to enrich the dictionary of custom words. (default: DEFAULT_COLUMNS_WHITESPACE_SPLIT)
        - specific_checkers: bool, flag to enable specific checkers (default: DEFAULT_SPECIFIC_CHECKERS_ENABLED)
        - specific_checkers_id: str, column name for specific checkers' identifiers (default: DEFAULT_SPECIFIC_CHECKERS_ID)
        """
        self.additional_language = additional_language
        self.spell_checkers = {"all": SpellChecker(self.additional_language, case_sensitive=True)}
        self.all_custom_words = set()
        self.corpus_file = corpus_file
        self.enable_specific_checkers = specific_checkers
        self.specific_checkers_id = specific_checkers_id
        self.corpus_cols_to_use = corpus_cols_to_use
        self.corpus_cols_spell_split = corpus_cols_spell_split
        self.corpus_cols_whitespace_split = corpus_cols_whitespace_split

        self.init_corpus()

    def init_corpus(self):
        """
        Initializes the corpus by loading custom words from corpus files.
        """
        df = self.load_xlsx_to_df(self.corpus_file)
        self.load_words(df, self.corpus_cols_to_use)
        self.load_splitted_words(df, self.corpus_cols_spell_split, use_spell_split=False)
        self.load_splitted_words(df, self.corpus_cols_whitespace_split, use_spell_split=True)

        if self.enable_specific_checkers:
            for id in df[self.specific_checkers_id].unique():
                self.spell_checkers[id] = SpellChecker(self.additional_language, case_sensitive=True)
                df_specific = df[df[self.specific_checkers_id] == id]
                self.load_words(df_specific, self.corpus_cols_to_use, id)
                self.load_splitted_words(df_specific, self.corpus_cols_spell_split, id, False)
                self.load_splitted_words(df_specific, self.corpus_cols_whitespace_split, id, True)

    def load_xlsx_to_df(self, file: str):
        """
        Loads an Excel file into a pandas DataFrame.

        Parameters:
        - file: str, path to the Excel file

        Returns:
        - df: pd.DataFrame, the loaded Excel file as a DataFrame
        """
        if not file.endswith(".xlsx"):
            raise ValueError("Invalid file format. The file must be in .xlsx format.")

        try:
            df = pd.read_excel(file)
            return df
        except Exception as e:
            raise Exception("Error loading Excel file:", e)

    def load_words(self, df: pd.DataFrame, col_names: list = [], spell_checker_key: str = "all"):
        """
        Loads custom words from a DataFrame into the spell checker.

        Parameters:
        - df: pd.DataFrame, the DataFrame containing the custom words
        - col_names: list, list of column names to load from (default: [])
        - spell_checker_key: str, key for the spell checker to load into (default: "all")
        """
        custom_words = []

        if col_names:
            df = df[col_names]
            for column in df.columns:
                loaded = df[column].dropna().astype(str)
                to_add = loaded.tolist()
                custom_words.extend(to_add)

        custom_words = [word.strip() for word in custom_words]

        self.all_custom_words.update(custom_words)
        self.spell_checkers[spell_checker_key].word_frequency.load_words(custom_words)

    def load_splitted_words(
        self, df: pd.DataFrame, col_names: list = [], spell_checker_key: str = "all", use_spell_split: bool = False
    ):
        """
        Loads splitted words from a DataFrame into the spell checker.

        Parameters:
        - df: pd.DataFrame, the DataFrame containing the splitted words
        - col_names: list, list of column names to load from (default: [])
        - spell_checker_key: str, key for the spell checker to load into (default: "all")
        - use_spell_split: bool, flag to indicate whether to use spell splitting or whitespace splitting (default: False)
        """
        custom_words = []

        if col_names:
            df = df[col_names]
            for column in df.columns:
                loaded = df[column].dropna().astype(str)
                for original_word in loaded:
                    words = (
                        self.spell_checkers[spell_checker_key].split_words(original_word)
                        if use_spell_split
                        else original_word.split()
                    )
                    custom_words.extend(words)

        custom_words = [word.strip() for word in custom_words]

        self.all_custom_words.update(custom_words)
        self.spell_checkers[spell_checker_key].word_frequency.load_words(custom_words)

    def print_dictionary(self, spell_checker_key: str = "all"):
        """
        Prints the dictionary of the spell checker.
        """
        pprint.pprint(self.spell_checkers[spell_checker_key].word_frequency.dictionary)

    def print_loaded_words(self):
        """
        Prints the set of all loaded custom words.
        """
        pprint.pprint(self.all_custom_words)

    def get_dictionary(self, spell_checker_key: str = "all"):
        """
        Returns the dictionary of the spell checker.

        Parameters:
        - spell_checker_key: str, key for the spell checker (default: "all")

        Returns:
        - dictionary: dict, the dictionary of the spell checker
        """
        return self.spell_checkers[spell_checker_key].word_frequency.dictionary

    def get_loaded_words(self):
        """
        Returns the set of all loaded custom words.

        Returns:
        - loaded_words: set, the set of all loaded custom words
        """
        return self.all_custom_words

    def save_dict_csv(self, path: str = "dictionary.csv", spell_checker_key: str = "all"):
        """
        Saves the dictionary of the spell checker to a CSV file.

        Parameters:
        - path: str, path to save the CSV file (default: "dictionary.csv")
        - spell_checker_key: str, key for the spell checker (default: "all")
        """
        d = self.get_dictionary(spell_checker_key)
        df = pd.DataFrame(d.items(), columns=["words", "count"])

        try:
            df.to_csv(path, index=False)
            print(f"Saved dictionary to '{path}'.")
        except Exception as e:
            print("Cannot write to file:", e)

    def check_best_candidate(self, string: str, spell_checker_key: str = "all"):
        """
        Suggests the best candidate for a misspelled string.

        Parameters:
        - string: str, the input string to suggest a correction for
        - spell_checker_key: str, key for the spell checker (default: "all")

        Returns:
        - suggested_candidate: str, the suggested best candidate for the misspelled string
        """
        corrected_words = self.spell_checkers[spell_checker_key].correction(string)

        if not corrected_words:
            return ""

        return corrected_words

    def check_best_candidate_split(self, string: str, spell_checker_key: str = "all"):
        """
        Suggests the best candidate for each word in a string.

        Parameters:
        - string: str, the input string to suggest corrections for
        - spell_checker_key: str, key for the spell checker (default: "all")

        Returns:
        - suggested_candidates: str, the suggested best candidates for each word in the string
        """
        words = string.split()
        corrected_words = [self.spell_checkers[spell_checker_key].correction(word) for word in words]

        if None in corrected_words:
            return ""

        return " ".join(corrected_words)

    def check_candidates(self, string: str, spell_checker_key: str = "all"):
        """
        Suggests multiple candidates for a misspelled string.

        Parameters:
        - string: str, the input string to suggest corrections for
        - spell_checker_key: str, key for the spell checker (default: "all")

        Returns:
        - suggested_candidates: list, the suggested candidates for the misspelled string
        """
        candidates = self.spell_checkers[spell_checker_key].candidates(string)

        if not candidates:
            return []

        return list(candidates)


if __name__ == "__main__":
    # NOTE: The following code provides examples on how to use the class above as well as testing it's functionality.
    
    sc = StringChecker()

    def test_best(test_str, specific="all"):
        """
        This function tests the 'check_best_candidate' method on a given string and prints the result.

        Args:
            test_str (str): The string to be tested.
            specific (str, optional): Specifies the specific completion method to be used. Defaults to "all".

        Prints:
            The function prints the input string followed by an arrow "->" and the result of the 'check_best_candidate' method.
        """
        print(test_str, "->", sc.check_best_candidate(test_str, specific))

    def test_best_split(test_str, specific="all"):
        """
        This function tests the 'check_best_candidate_split' method on a given string and prints the result.

        Args:
            test_str (str): The string to be tested.
            specific (str, optional): Specifies the specific completion method to be used. Defaults to "all".

        Prints:
            The function prints the input string followed by an arrow "->" and the result of the 'check_best_candidate_split' method.
        """        
        print(test_str, "->", sc.check_best_candidate_split(test_str, specific))

    def test_candidates(test_str, specific="all"):
        """
        This function tests the 'check_candidates' method on a given string and prints the result.

        Args:
            test_str (str): The string to be tested.
            specific (str, optional): Specifies the specific completion method to be used. Defaults to "all".

        Prints:
            The function prints the input string followed by an arrow "->" and the result of the 'check_candidates' method.
        """
        print(test_str, "->", sc.check_candidates(test_str, specific))

    def test_all(test_str, specific="all"):
        """
        This function tests all three completion methods on a given string and prints the results.

        Args:
            test_str (str): The string to be tested.
            specific (str, optional): Specifies the specific completion method to be used. Defaults to "all".

        Prints:
            The function calls 'test_best', 'test_best_split', and 'test_candidates' functions with the same test string and specific method.
        """        
        test_best(test_str, specific)
        test_best_split(test_str, specific)
        test_candidates(test_str, specific)

    # Test StringChecker with 'check_best_candidate'
    print("\n# Test StringChecker with 'check_best_candidate'")
    test_best("Simens", )
    test_best("Simens")
    test_best("S7 1500")
    test_best("S7:1500")
    test_best("Beckhoff")
    test_best("XCM325")
    test_best("Plcnext")

    # Test StringChecker with 'check_best_candidate_split'
    print("\n# Test StringChecker with 'check_best_candidate_split'")
    test_best_split("Simens")
    test_best_split("S7 1500")
    test_best_split("S7:1500")
    test_best_split("Beckhoff")
    test_best_split("AXCF 2152")

    # Test StringChecker with 'check_candidates'
    print("\n# Test StringChecker with 'check_candidates'")
    test_candidates("Simens")
    test_candidates("S7 1501")
    test_candidates("S7-1512-1")
    test_candidates("S7:1513-2")
    test_candidates("Beckhoff")
    test_candidates("XCM325")
    test_candidates("Plcnext")
    test_candidates("S6")
