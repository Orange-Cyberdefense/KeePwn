import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [x.strip() for x in f.readlines()]

setuptools.setup(
    name="keepwn",
    version="0.4.0",
    author="Julien Bedel - @d3lb3_",
    author_email="d3lb3@protonmail.com",
    description="A python tool to automate KeePass discovery and secret extraction.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Orange-Cyberdefense/keepwn",
    packages=['keepwn', 'keepwn.core', 'keepwn.utils'],
    package_data={'keepwn': ['keepwn/']},
    include_package_data=True,
    license="GPL3",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=requirements,
    entry_points={
        'console_scripts': ['KeePwn=keepwn.__main__:main']
    }
)