"""
    Note: String matching can be improved by implementing different distance metrics.
    For example, when multiple results are found, preference can be given to results with just a two-character
    difference, such as when neighboring characters are switched, as in 'Test' and 'Tset'."
"""

import yaml
import regex
import pandas as pd
import os

IS_LEV = False
try:
    import Levenshtein
except ModuleNotFoundError:

    IS_LEV = False
else:
    IS_LEV = True

# NOTE: The following definitions are used by default and can be customized if changes are made to the regex collection or corpus.

# Default path to the file containing a regex collection (file type .yaml) used for regex matching. Modify file and path if using a custom file.
DEFAULT_REGEX_COLLECTION_FILE = os.path.join(os.path.dirname(__file__), "data/re_data.yaml")
# Default list of the regex categories to use from the regex collection file. Add or remove entries from the list to limit or extend the regex matching. Ensure that the spelling matches the entries in the regex file.
DEFAULT_REGEX_CATEGORIES = ["Device Family", "Device Type", "Article Number", "Version"]
# Default path to the corpus file (file type .xlsx) used for levenshtein distance matching. Modify the corpus file and path for custom data.
DEFAULT_CORPUS_FILE = os.path.join(os.path.dirname(__file__), "data/device_list.xlsx")
# Default list of columns to use from the corpus file. Add or remove column entries from the list to limit or extend the levenshtein distance matching. Ensure that the spelling matches the columns from the corpus file.
DEFAULT_CORPUS_COLUMNS = ["Device Family", "Device Type", "Article Number"]
# Default column for filtering, here manufacturer specific filtering from the corpus file.
DEFAULT_FILTER_COLUMN = "Manufacturer"


class StringMiner:
    """
    The StringMiner class provides methods for matching target strings with regular expressions and levenshtein distance.
    """

    def __init__(
        self,
        regex_collection_path: str = DEFAULT_REGEX_COLLECTION_FILE,
        regex_categories: list = DEFAULT_REGEX_CATEGORIES,
        corpus_path: str = DEFAULT_CORPUS_FILE,
        corpus_search_cols: list = DEFAULT_CORPUS_COLUMNS,
        corpus_filter_col: str = DEFAULT_FILTER_COLUMN,
    ):
        """
        Initializes the StringMiner object.

        Parameters:
        - regex_collection_path: str, Path to the file containing a regex collection (file type .yaml) used for regex matching. Modify file and path if using a custom file.
        - regex_categories: list, A list of the regex categories to use from the regex collection file. Add or remove entries from the list to limit or extend the regex matching.
        - corpus_path: str, Path to the corpus file (file type .xlsx) used for levenshtein distance matching. Modify the corpus file and path for custom data.
        - corpus_search_cols: list, A list of columns to use from the corpus file. Add or remove column entries from the list to limit or extend the levenshtein distance matching.
        - corpus_manufacturer_col: str, The column for filtering, here manufacturer specific filtering from the corpus file.
        """
        # Load the regular expressions from the file
        with open(regex_collection_path, "r") as file:
            self.regex_dict = yaml.safe_load(file)

        # Read the search strings from the Excel file
        self.search_strings_df = pd.read_excel(corpus_path)
        self.search_strings_df.fillna("", inplace=True)
        self.re_attributes = regex_categories
        self.corpus_search_cols = corpus_search_cols
        self.corpus_vendor_col = corpus_filter_col

    def match(
        self, target_string: str, vendor_filter: str = "", ignore_case: bool = False, strip_target: bool = False
    ):
        """
        Matches a target string with search strings using fuzzy matching and returns the matching attributes as a dictionary.

        Parameters:
        - target_string: str, the target string to match with search strings
        - vendor_filter: str, the vendor name to filter the search strings (default: "")
        - ignore_case: bool, whether to ignore case when matching (default: False)
        - strip_target: bool, whether to strip leading/trailing whitespace from the target string (default: False)

        Returns:
        - result: dict, a dictionary mapping attribute names to matching values
        """
        return self.match_fuzzy(target_string, 0, vendor_filter, ignore_case, strip_target)

    def match_fuzzy(
        self,
        target_string: str,
        max_errors: int = 1,
        vendor_filter: str = "",
        ignore_case: bool = False,
        strip_target: bool = False,
    ):
        """
        Matches a target string with search strings using fuzzy matching and returns the matching attributes as a dictionary.

        Parameters:
        - target_string: str, the target string to match with search strings
        - max_errors: int, the maximum number of errors allowed in the fuzzy matching (default: 1)
        - vendor_filter: str, the vendor name to filter the search strings (default: "")
        - ignore_case: bool, whether to ignore case when matching (default: False)
        - strip_target: bool, whether to strip leading/trailing whitespace from the target string (default: False)

        Returns:
        - result: dict, a dictionary mapping attribute names to matching values
        """
        result = {}
        re_flags = 0
        if ignore_case:
            re_flags = regex.IGNORECASE
        if strip_target:
            target_string = target_string.strip()

        for attribute in self.re_attributes:
            if (
                matching_attributes := self._match_attribute_fuzzy(
                    target_string, max_errors, attribute, vendor_filter, re_flags
                )
            ) != None:
                if matching_attributes:
                    result[attribute] = matching_attributes

        return result

    def _match_attribute_fuzzy(
        self, target_string: str, max_errors: int, attribute: str, vendor_filter: str = "", re_flag=regex.BESTMATCH
    ):
        """
        Matches a target string with a fuzzy regular expression for a specific attribute and returns the matching string or None.

        Parameters:
        - target_string: str, the target string to match with the fuzzy regular expression
        - max_errors: int, the maximum number of errors allowed in the fuzzy matching
        - attribute: str, the attribute name to match with the fuzzy regular expression
        - vendor_filter: str, the vendor name to filter the search strings (default: "")
        - re_flag: int, the flag for the fuzzy matching algorithm (default: regex.BESTMATCH)

        Returns:
        - result: str or None, the matching string or None if no match is found
        """
        result = None
        for k, regex_str in self.regex_dict[attribute].items():
            if not regex_str:
                continue
            if vendor_filter and vendor_filter != k:
                continue
            if type(regex_str) is list:
                for re_list in regex_str:
                    for i in range(max_errors + 1):
                        pattern = "(?:" + re_list + "){e<=" + str(i) + "}"
                        if match := regex.search(pattern, target_string, flags=re_flag):
                            result = match.group(0)
                            break
                    if result != None:
                        break
            else:
                for i in range(max_errors + 1):
                    pattern = "(?:" + regex_str + "){e<=" + str(i) + "}"
                    if match := regex.search(pattern, target_string, flags=re_flag):
                        result = match.group(0)
                        break
                if result != None:
                    break
        return result

    def _find_similar_substrings(self, target_string, search_string, threshold):
        """
        Finds similar substrings in a target string based on Levenshtein distance.

        Parameters:
        - target_string: str, the target string to search for similar substrings
        - search_string: str, the search string to compare with substrings in the target string
        - threshold: float, the minimum similarity score threshold for a substring to be considered similar

        Returns:
        - similar_substrings: list, a list of tuples containing the similar substrings and their similarity scores
        """
        if not IS_LEV:
            return None

        similar_substrings = []

        for i in range(len(target_string) - len(search_string) + 1):
            substring = target_string[i : i + len(search_string)]
            distance = Levenshtein.distance(substring, search_string)
            similarity_score = 1 - (distance / max(len(substring), len(search_string)))

            if similarity_score >= threshold:
                similar_substrings.append((substring, similarity_score))

        return similar_substrings

    def match_levenshtein(
        self, target_string: str, threshold: float = 0.85, vendor_filter: str = "", strip_target: bool = False
    ):
        """
        Matches a target string with search strings using Levenshtein distance and returns the matching attributes as a dictionary.

        Parameters:
        - target_string: str, the target string to match with search strings
        - threshold: float, the minimum similarity score threshold for a substring to be considered a match (default: 0.85)
        - vendor_filter: str, the vendor name to filter the search strings (default: "")
        - strip_target: bool, whether to strip leading/trailing whitespace from the target string (default: False)

        Returns:
        - result_dict: dict, a dictionary mapping attribute names to matching values
        """
        if not IS_LEV:
            return None

        results = []
        if strip_target:
            target_string = target_string.strip()

        if vendor_filter:
            search_df = self.search_strings_df[self.search_strings_df[self.corpus_vendor_col] == vendor_filter]
            search_df = search_df[self.corpus_search_cols]
        else:
            search_df = self.search_strings_df[self.corpus_search_cols]

        for _, search_attributes in search_df.iterrows():
            for search_key, search_string in search_attributes.items():
                if search_string:
                    res = self._find_similar_substrings(target_string, str(search_string), threshold)
                    if len(res) > 0:
                        for r in res:
                            results.append([search_key, r[0].strip(), r[1]])
        result_df = pd.DataFrame(results, columns=["attribute", "value", "confidence"])
        result_df.drop_duplicates(inplace=True)
        result_df["confidence"] = pd.to_numeric(result_df["confidence"])
        max_confidence_indices = result_df.groupby("attribute")["confidence"].idxmax()
        result_df = result_df.loc[max_confidence_indices]
        result_df.drop("confidence", axis=1, inplace=True)
        result_dict = result_df.set_index("attribute").to_dict()["value"]

        return result_dict


if __name__ == "__main__":
    # NOTE: The following code provides examples on how to use the class above as well as testing it's functionality.
    sm = StringMiner()

    def test_all(target_string, vendor_filter="Siemens"):
        """
        This function tests various matching methods on a target string and prints the results.

        Args:
            target_string (str): The string to be tested.
            vendor_filter (str, optional): The vendor filter to be applied. Defaults to "Siemens".

        Prints:
            The function prints the results of three matching methods on the target string:
            - Normal RE: The result of a normal regex match with the vendor filter.
            - Fuzzy RE: The result of a fuzzy regex match with the vendor filter and maximum 1 error allowed.
            - Levenshtein: The result of a Levenshtein distance match with the vendor filter.
        """        
        print(f"\nTesting: '{target_string}'")
        print("Normal RE  : ", sm.match(target_string, vendor_filter=vendor_filter))
        print("Fuzzy RE   : ", sm.match_fuzzy(target_string, vendor_filter=vendor_filter, max_errors=1))
        print("Levenshtein: ", sm.match_levenshtein(target_string, vendor_filter=vendor_filter))

    test_nmap = [
        "annotation: SIMATIC S7-1500                   6ES7 672-5DC01-0YA0      0 V  2  1  7\x00",
        "annotation: SIMATIC S7-1200                   6ES7 212-1AE40-0XB0      7 V  4  5  1\x00",
        "annotation: SIMATIC S7-1500                   6ES7 672-5DC01-0YA0      0 V2.1.7\x00",
        "annotation: SIMATIC S7-1200                   6ES7 212-1AE40-0XB0      7 V4.5.1\x00",
        "annotation: SIMATIC S7-1500                   6ES7 672-5DC01-0YA0      0 V 2.1.7\x00",
        "annotation: SIMATIC S7-1200                   6ES7 212-1AE40-0XB0      7 V 4.5.1\x00",
        "annotation: S7-1200                   6ES7 212-1AE40-0XB0      7 V  4  5  1\x00",
        "annotation: S7-1500                   6ES7 512-1DK01-0AB0      4 V  2  9  2\x00",
        "annotation: AXL F BK PN               2701815                  2 V  1  0  4\x00",
        "annotation: JVL-MOTOR                 MIS340C12EPH285          4 V  3 40 12\x00",
        "annotation: S7=1500                   6ES7672-5DC01-0YA0      0 V  2  1  7\x00",
        "annotation: S71200                   6ES7:212-1AE40-0XB0      7 V  4  5  1\x00",
        "annotation: S6-1200                   6ES7 212-1AE40-0XB0      7 V  4  5  1\x00",
        "annotation: S7-150                    6ES7 512-1DK01:0AB0      4 V  2  9  2\x00",
        "annotation: AXL F BK PN               2701815                  2 V  1  0  4\x00",
        "annotation: JVL-MOTOR                 MIS340C12EPH285          4 V  3 40 12\x00",
        "annotation: PlcNext Axc f 2152",
        "SIMATIC CP 1623 (6GK1162-3AA00)",
        "SIMATIC CP 1628 (6GK1162-8AA00)",
        "SIMATIC CP 1543-1 (6GK7543-1AX00-0XE0)",
        "SIMATIC MV540 H (6GF3540-0GE10)",
        "SIMATIC MV550 H (6GF3550-0GE10)",
        "SIMATIC MV560 U (6GF3560-0LE10)",
        "RUGGEDCOM RM1224 family (6GK6108-4AM00)"
    ]

    # ----------- default regex ----------- #
    print("\n# ----------- default regex ----------- #")
    for l in test_nmap:
        print(sm.match(l))

    # ----------- default regex only Siemens ----------- #
    print("\n# ----------- default regex only Siemens ----------- #")
    for l in test_nmap:
        print(sm.match(l, vendor_filter="Siemens"))

    # ----------- default regex only PhoenixContact ----------- #
    print("\n# ----------- default regex only PhoenixContact ----------- #")
    for l in test_nmap:
        print(sm.match(l, vendor_filter="Phoenix Contact"))

    # ----------- default regex stripping whitespaces + ignorecase ----------- #
    print("\n# ----------- default regex stripping whitespaces + ignorecase ----------- #")
    for l in test_nmap:
        print(sm.match(l, strip_target=True, ignore_case=True))

    # ----------- Tests with fuzzy regex ----------- #
    print("\n# ----------- Tests with fuzzy regex ----------- #")
    for l in test_nmap:
        print(sm.match_fuzzy(l, max_errors=1))

    # ----------- Tests with levenshtein distance ----------- #
    print("\n# ----------- Tests with levenshtein distance ----------- #")
    for l in test_nmap:
        print(sm.match_levenshtein(l, 0.8))

    # ----------- Tests with levenshtein distance only Siemens ----------- #
    print("\n# ----------- Tests with levenshtein distance ----------- #")
    for l in test_nmap:
        print(sm.match_levenshtein(l, threshold=0.85, vendor_filter="Siemens"))

    # ----------- Some manual test string provided by BSI ----------- #
    test_all("SSA-350757: Improper Access Control [...] Related ET200 CPUs and SIPLUS variants.")
    test_all("SSA-350757: Improper Access Control [...] Related ET 200 CPUs and SIPLUS variants.")
    test_all("SIMATIC CP 1623 (6GK1162-3AA00)")
    test_all("SIMATIC CP 1628 (6GK1162-8AA00)")
    test_all("SIMATIC CP 1543-1 (6GK7543-1AX00-0XE0)")
    test_all("SIMATIC MV540 H (6GF3540-0GE10)")
    test_all("SIMATIC MV550 H (6GF3550-0GE10)")
    test_all("SIMATIC MV560 U (6GF3560-0LE10)")
    test_all("RUGGEDCOM RM1224 family (6GK6108-4AM00)")

    # ----------- Tests with data from Siemens CSAF files ----------- #
    print("\n# Test StringChecker with data from Siemens CSAF files")
    test_all(
        "SIMATIC S7-400 CPU devices contain an input validation vulnerability that could allow an attacker to create a Denial-of-Service condition."
    )
    test_all(
        "A restart is needed to restore normal operations.\n\nSiemens has released an update for SIMATIC S7-410 V10 CPU family"
    )
    test_all("and SIMATIC S7-400 H V6 CPU family.")
    test_all("(incl. SIPLUS variants for both) and recommends to update to the latest version.")
    test_all("Affected models of the S7-1500 CPU product family do not contain an Immutable Root of Trust in Hardware.")
    test_all("Two vulnerabilities have been identified in the SIMATIC S7-400 CPU family.")
    test_all("Multiple Vulnerabilities in SCALANCE SC-600 Family before V3.0")
    test_all("Multiple vulnerabilities affecting various third-party components of the SCALANCE SC-600 family.")
    test_all(
        "SIMATIC S7-1500 CPUs and related products protect the built-in global private key in a way that cannot be considered sufficient any longer."
    )
    test_all(
        "SIMATIC S7-1200 CPUs and related products protect the built-in global private key in a way that cannot be considered sufficient any longer."
    )
    test_all("Vulnerabilities in Third-Party Component Mbed TLS of LOGO! CMR Family and SIMATIC RTU 3000 Family")
    test_all("Web Vulnerabilities in SCALANCE S-600 Family")
    test_all(
        "SIMATIC S7-400 CPU devices contain an input validation vulnerability that could allow an attacker to create a Denial-of-Service condition."
    )
    test_all(
        "A restart is needed to restore normal operations.\n\nSiemens has released an update for SIMATIC S7-410 V10 CPU family"
    )
    test_all("and SIMATIC S7-400 H V6 CPU family")
    test_all("(incl. SIPLUS variants for both)")
    test_all("Improper Access Control Vulnerability in TIA Portal Affecting S7-1200 and ... Web Server")
    test_all("Improper Access Control Vulnerability in TIA Portal Affecting ... and S7-1500 CPUs Web Server")
    test_all("(Incl. Related ET200 CPUs and SIPLUS variants)")
