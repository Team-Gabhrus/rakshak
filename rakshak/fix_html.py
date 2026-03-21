import re

with open("app/templates/cbom.html", "r") as f:
    text = f.read()

pattern = r"  \}  const opts = cbomSnapshots\.map.*?document\.getElementById\('snapB'\)\.innerHTML = opts;\n  \}"

fixed = """  }"""

text = re.sub(pattern, fixed, text, flags=re.DOTALL)

with open("app/templates/cbom.html", "w") as f:
    f.write(text)
print("done")
