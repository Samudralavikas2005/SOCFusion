import unittest
from src.attack_chain.simplifier import simplify_technique_chain


class TestSimplifyTechniqueChain(unittest.TestCase):

    def test_prompt_example_1(self):
        """
        Input: [T1021.006, T1105, T1021.006, T1003.003]
        Expected: [T1021.006, T1105, T1003.003]
        """
        inp = ["T1021.006", "T1105", "T1021.006", "T1003.003"]
        expected = ["T1021.006", "T1105", "T1003.003"]
        self.assertEqual(simplify_technique_chain(inp), expected)

    def test_prompt_example_2(self):
        """
        Input: [A, A, B, B, C]
        Expected: [A, B, C]
        """
        inp = ["A", "A", "B", "B", "C"]
        expected = ["A", "B", "C"]
        self.assertEqual(simplify_technique_chain(inp), expected)

    def test_prompt_example_3(self):
        """
        Input: [A, B, A, C, B, D]
        Expected: [A, B, C, D]
        """
        inp = ["A", "B", "A", "C", "B", "D"]
        expected = ["A", "B", "C", "D"]
        self.assertEqual(simplify_technique_chain(inp), expected)

    def test_prompt_example_4(self):
        """
        Input: [None, "", A, A, B]
        Expected: [A, B]
        """
        inp = [None, "", "A", "A", "B"]
        expected = ["A", "B"]
        self.assertEqual(simplify_technique_chain(inp), expected)

    def test_full_user_prompt_chain(self):
        """
        Full example from user prompt:
        T1021.006 -> T1105 -> T1021.006 -> T1003.003 -> T1021.006 -> T1053.005 ->
        T1087.002 -> T1016 -> T1105 -> T1021.006 -> T1105 -> T1021.006 -> T1105 ->
        T1562.001 -> T1021.006 -> T1105 -> T1021.006 -> T1105 -> T1016 ->
        T1021.006 -> T1087.002 -> T1021.006 -> T1562.001 -> T1105 -> T1021.006 -> T1105
        """
        inp = [
            "T1021.006", "T1105", "T1021.006", "T1003.003", "T1021.006", "T1053.005",
            "T1087.002", "T1016", "T1105", "T1021.006", "T1105", "T1021.006", "T1105",
            "T1562.001", "T1021.006", "T1105", "T1021.006", "T1105", "T1016",
            "T1021.006", "T1087.002", "T1021.006", "T1562.001", "T1105", "T1021.006", "T1105"
        ]
        expected = [
            "T1021.006", "T1105", "T1003.003", "T1053.005", "T1087.002", "T1016", "T1562.001"
        ]
        self.assertEqual(simplify_technique_chain(inp), expected)

    def test_dict_events(self):
        """
        Test handling of event dictionaries containing technique_id or technique key.
        """
        inp = [
            {"technique_id": "T1021.006"},
            {"technique_id": None},
            {"technique_id": ""},
            {"technique": "T1105"},
            {"predicted_technique": "T1021.006"},
            {"technique_id": "T1003.003"},
        ]
        expected = ["T1021.006", "T1105", "T1003.003"]
        self.assertEqual(simplify_technique_chain(inp), expected)

    def test_empty_and_null_inputs(self):
        self.assertEqual(simplify_technique_chain([]), [])
        self.assertEqual(simplify_technique_chain(None), [])
        self.assertEqual(simplify_technique_chain([None, "", "  "]), [])


if __name__ == "__main__":
    unittest.main()
