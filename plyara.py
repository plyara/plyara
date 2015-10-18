import interp.yaralexer
import ply.yacc as yacc

import sys
import json


if __name__ == "__main__":

  if len(sys.argv) > 1:
    file_name = sys.argv[1]
    dictRules = dictionaryFromRulesFile(file_name)
    for rule in dictRules:
      print(json.dumps(rule) + "\n")
