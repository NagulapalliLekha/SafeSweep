from setuptools import setup
import pathlib
HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()
setup(
    name                =   "safesweep",
    version             =   '1.0',
    description         =   "Web Vulnerability Scanner.",
    long_description    =   README,
    long_description_content_type = "text/markdown",
    author              =   "Deepak,Lekha,Surya",
    py_modules          =   ['safesweep',],
    install_requires    =   [],
    python_requires=">=3.6",
)
