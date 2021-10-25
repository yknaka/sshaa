import setuptools
with open("README.md", "r", encoding="utf-8") as fh:
  long_description = fh.read()

setuptools.setup(
    name="yknsshanalysis",
    version="1.1.2",
    author="Yuki NAKAMURA",
    author_email="naka_yk@live.jp",
    description="Analyze auth.log",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yknaka/yknsshanalysis",
    project_urls={
        "Analyze ssh auth.log": "https://github.com/yknaka/yknsshanalysis",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    py_modules=['yknsshanalysis'],
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            'yknsshanalysis = yknsshanalysis:main'
        ]
    },
)
