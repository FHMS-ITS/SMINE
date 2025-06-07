from typing import Dict, List, Optional, Union


class CrtBundleMask:
    def __init__(self, initial_bitmask: Optional[Union[int, str]] = None):
        """
        Initialize the BitMaskManager with a list of strings.
        Each string corresponds to a specific bit in the bitmask.

        :param initial_bitmask: Optional bitmask to initialize the bit mask, either as an int or a string.
        """
        self.strings: List[str] = [
            "mozilla",
            "microsoft",
            "macOS",
            "chrome",
            "cencys",
            "ccadb",
            "smine",
        ]
        self.bit_mask: int = 0
        self.string_to_bit: Dict[str, int] = {
            string: 1 << idx for idx, string in enumerate(self.strings)
        }

        if isinstance(initial_bitmask, int):
            self.bit_mask = initial_bitmask
        elif isinstance(initial_bitmask, str):
            self.set_bit(initial_bitmask)
        elif initial_bitmask is not None:
            raise TypeError(
                f"Invalid type for initial_bitmask: {type(initial_bitmask).__name__}"
            )

    def set_bit(self, string: str) -> None:
        """
        Set the bit corresponding to the given string.
        If the string matches or is contained within other strings, those bits are set too.

        :param string: The string to set the bit for.
        """
        for key in self.strings:
            if key in string:
                self.bit_mask |= self.string_to_bit[key]

    def set_bits_from_mask(self, mask: int) -> None:
        """
        Set bits in the current bitmask based on another bitmask.

        :param mask: The bitmask whose bits should be set in the current bitmask.
        """
        self.bit_mask |= mask

    def calculate_bit_mask(self) -> int:
        """
        Get the current value of the bit mask.

        :return: The current bitmask as an integer.
        """
        return self.bit_mask

    def create_dict_from_mask(self) -> Dict[str, int]:
        """
        Create a dictionary showing which strings are set in the bit mask.

        :return: A dictionary with strings as keys and 1 (set) or 0 (not set) as values.
        """
        return {
            string: int(bool(self.bit_mask & bit))
            for string, bit in self.string_to_bit.items()
        }
